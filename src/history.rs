use ansi_term;
use chrono::prelude::*;
use flate2::read::GzDecoder;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::ops::Add;
use std::path::PathBuf;
use std::{fs, io};
use stybulate::{Cell, Headers, Style, Table};

const APT_LOG_PATH: &str = "/var/log/apt";
const APT_HISTORY_LOG_PATTERN: &str = r"history\.log(\.[0-9]+\.gz)?";
const COMMAND_LINE_ELLIPSIS: &str = " <...>";
const HEADERS: [&str; 5] = [
    "ID",
    "Command line",
    "Date and time",
    "Action(s)",
    "Altered",
];
const INFO_DATE_FORMAT: &str = "%a %b %e %T %Y";
const LIST_DATE_FORMAT: &str = "%F %H:%M";
const LOG_FILE_DATE_FORMAT: &str = "%F  %T";
const MAX_COMMAND_LINE_LEN: usize = 100;

#[derive(Clone)]
struct HistoryEntry {
    action: String,
    affected: HashMap<String, String>,
    altered: usize,
    command_line: String,
    end_date: NaiveDateTime,
    id: u32,
    start_date: NaiveDateTime,
}

impl HistoryEntry {
    fn new() -> HistoryEntry {
        HistoryEntry {
            ..Default::default()
        }
    }
}

impl Default for HistoryEntry {
    fn default() -> Self {
        HistoryEntry {
            action: "".to_string(),
            affected: HashMap::new(),
            altered: 0,
            command_line: "".to_string(),
            end_date: Local::now().naive_local(),
            id: 0,
            start_date: Local::now().naive_local(),
        }
    }
}

fn finalize_entry(entry: &mut HistoryEntry, index: u32) {
    entry.id = index;

    let mut command_line = entry.command_line.clone();
    if command_line.len() > MAX_COMMAND_LINE_LEN {
        command_line = command_line[0..MAX_COMMAND_LINE_LEN - COMMAND_LINE_ELLIPSIS.len()]
            .to_string()
            .add(COMMAND_LINE_ELLIPSIS);
    }
    if command_line.starts_with("apt ") {
        command_line = command_line[4..].to_string();
    }
    entry.command_line = command_line;

    let mut altered = 0;
    for affected in entry.affected.values() {
        altered += affected.match_indices("),").count() + 1;
    }
    entry.altered = altered;
}

fn entries_from_file(filename: &str, index_start: u32) -> Vec<HistoryEntry> {
    let log = File::open(filename).unwrap();
    let reader: Box<dyn BufRead> = if filename.ends_with(".gz") {
        let gz = GzDecoder::new(log);
        Box::new(io::BufReader::new(gz))
    } else {
        Box::new(io::BufReader::new(log))
    };

    let mut entries = vec![];
    let mut entry = HistoryEntry::new();
    let mut index = index_start;
    let mut seen_entry = false;

    for line in reader.lines() {
        let line = line.unwrap();

        if line.is_empty() {
            if !seen_entry {
                seen_entry = true;
                continue;
            }

            finalize_entry(&mut entry, index);
            entries.push(entry);
            index += 1;
            entry = HistoryEntry::new();
            continue;
        }

        let mut fields = line.split(": ");
        let descriptor = fields.nth(0).unwrap();
        let value = fields
            .last()
            .expect(format!("error processing line `{}`", line).as_str());

        match descriptor {
            "Commandline" => entry.command_line = value.to_string(),
            "End-Date" => {
                entry.end_date = NaiveDateTime::parse_from_str(value, LOG_FILE_DATE_FORMAT)
                    .expect("error parsing end date")
            }
            "Start-Date" => {
                entry.start_date = NaiveDateTime::parse_from_str(value, LOG_FILE_DATE_FORMAT)
                    .expect("error parsing start date");
            }
            "Install" | "Purge" | "Reinstall" | "Remove" | "Upgrade" => {
                entry.action = descriptor.to_string();
                entry
                    .affected
                    .insert(descriptor.to_string(), value.to_string());
            }
            "Error" | "Requested-By" => {}
            _ => panic!("unknown field {}", descriptor),
        }
    }

    // Last line is not empty.
    finalize_entry(&mut entry, index);
    entries.push(entry);
    entries
}

fn history_entries() -> Vec<HistoryEntry> {
    let log_file_regex = Regex::new(APT_HISTORY_LOG_PATTERN).expect("error parsing file regex");
    let mut history_files: Vec<PathBuf> = vec![];

    for entry in fs::read_dir(APT_LOG_PATH).expect("error reading apt log path") {
        let entry = entry.expect("error reading dir entry");
        let filename = entry.file_name();
        let filename = filename.to_str().expect("error reading file name");
        if log_file_regex.is_match(filename) {
            history_files.push(entry.path());
        }
    }

    let mut combined: Vec<HistoryEntry> = vec![];
    let mut id: u32 = 1;
    for file in history_files {
        let entries = entries_from_file(file.to_str().expect("error getting file path"), id);
        let num_entries = entries.len() as u32;
        combined.extend(entries);
        id += num_entries;
    }

    combined
}

fn get_affected(affected: &str) -> Vec<String> {
    let mut out: String = String::new();
    let mut discard_next = false;
    let mut inside_parens = false;
    let mut pkgs: Vec<String> = vec![];

    for c in affected.chars() {
        match c {
            '(' => {
                inside_parens = true;
                pkgs.push(out.trim().to_string());
                out = String::new();
                continue;
            }
            ')' => {
                inside_parens = false;
                discard_next = true;
                continue;
            }
            _ => {}
        }

        if inside_parens {
            continue;
        }
        if discard_next {
            discard_next = false;
            continue;
        }

        out.push(c);
    }

    pkgs
}

pub fn info(id: Option<u32>) {
    let entries = history_entries();
    let id = id
        .or(Some(entries.len() as u32))
        .expect("error getting ID of history entry");
    let id = id as usize;
    // IDs are 1-indexed
    if id > entries.len() {
        eprintln!("No entry with ID {id}");
        return;
    }

    let entry = entries.get(id - 1).unwrap();
    let duration = entry.end_date - entry.start_date;
    let end_time = format!(
        "{} ({} seconds)",
        entry.end_date.format(INFO_DATE_FORMAT),
        duration.num_seconds()
    );

    let mut header_table = tabular::Table::new("{:<}: {:<}");
    header_table.add_row(
        tabular::Row::new()
            .with_cell("Transaction ID")
            .with_cell(id),
    );
    header_table.add_row(
        tabular::Row::new()
            .with_cell("Begin time")
            .with_cell(&entry.start_date.format(INFO_DATE_FORMAT)),
    );
    header_table.add_row(
        tabular::Row::new()
            .with_cell("End time")
            .with_cell(end_time),
    );
    header_table.add_row(
        tabular::Row::new()
            .with_cell("Command Line")
            .with_cell(&entry.command_line),
    );
    header_table.add_row(tabular::Row::new().with_cell("Comment").with_cell(""));

    print!("{header_table}");
    println!("Packages Altered:");

    let mut pkgs_table = tabular::Table::new("    {:>} {:<}");
    let mut actions: Vec<_> = entry.affected.keys().collect();
    actions.sort();

    let style = ansi_term::Style::new().bold();
    for action in actions {
        let pkgs = entry
            .affected
            .get(action)
            .expect("unexpected entry miss in map");
        let mut ordered = get_affected(pkgs);
        ordered.sort();
        for pkg in ordered {
            pkgs_table.add_row(
                tabular::Row::new()
                    .with_cell(style.paint(action))
                    .with_cell(pkg),
            );
        }
    }

    print!("{pkgs_table}");
}

pub fn list(reverse: bool) {
    let mut entries = history_entries();

    // Default behavior of dnf is to list entries in descending order by ID, the entries we get by
    // parsing history logs is in ascending order by default.
    if !reverse {
        entries.reverse();
    }

    let mut rows: Vec<Vec<Cell>> = Vec::new();
    entries.iter().for_each(|entry| {
        let row = vec![
            Cell::Int(entry.id as i32),
            Cell::from(&entry.command_line),
            Cell::from(&entry.start_date.format(LIST_DATE_FORMAT).to_string()),
            Cell::from(&entry.action),
            Cell::Int(entry.altered as i32),
        ];
        rows.push(row);
    });

    let table = Table::new(Style::Presto, rows, Some(Headers::from(HEADERS.to_vec()))).tabulate();
    println!("{}", table);
}
