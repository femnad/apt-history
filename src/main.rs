use std::fs::File;
use std::io;
use std::io::BufRead;
use std::ops::Add;

use clap::Parser;
use stybulate::{Cell, Headers, Style, Table};

const APT_HISTORY_LOG: &str = "/var/log/apt/history.log";
const COMMAND_LINE_ELLIPSIS: &str = " <...>";
const HEADERS: [&str; 5] = [
    "ID",
    "Command line",
    "Date and time",
    "Action(s)",
    "Altered",
];
const MAX_COMMAND_LINE_LEN: usize = 100;

#[derive(Clone)]
struct HistoryEntry {
    action: String,
    altered: usize,
    affected: String,
    command_line: String,
    end_date: String,
    start_date: String,
    id: u32,
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
            affected: "".to_string(),
            altered: 0,
            command_line: "".to_string(),
            end_date: "".to_string(),
            id: 0,
            start_date: "".to_string(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    reverse: bool,

    #[arg(default_value = "list")]
    command: String,

    id: Option<u32>,
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

    entry.altered = entry.affected.match_indices("),").count() + 1;
}

fn history_entries() -> Vec<HistoryEntry> {
    let log = File::open(APT_HISTORY_LOG).unwrap();
    let reader = io::BufReader::new(log);

    let mut seen_entry = false;
    let mut index = 1;

    let mut entries = vec![];
    let mut entry = HistoryEntry::new();

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
            "End-Date" => entry.end_date = value.to_string(),
            "Start-Date" => entry.start_date = value.to_string(),
            "Install" | "Purge" | "Reinstall" | "Remove" | "Upgrade" => {
                entry.action = descriptor.to_string();
                if entry.affected.is_empty() {
                    entry.affected = value.to_string();
                } else {
                    entry.affected = format!(" {}", entry.affected)
                }
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

fn get_affected(affected: &str) -> Vec<String> {
    let mut out : String = String::new();
    let mut discard_next = false;
    let mut inside_parens = false;
    let mut pkgs: Vec<String> = vec!();

    for c in affected.chars() {
        match c {
            '(' => {
                inside_parens = true;
                pkgs.push(out.trim().to_string());
                out = String::new();
                continue
            },
            ')' => {
                inside_parens = false;
                discard_next = true;
                continue
            },
            _ => {},
        }

        if inside_parens {
            continue
        }
        if discard_next {
            discard_next = false;
            continue
        }

        out.push(c);
    }

    pkgs
}

fn info(args: Args) {
    let entries = history_entries();
    let id = args.id.unwrap() as usize;
    let entry = entries.get(id-1).unwrap();
    let affected = get_affected(&entry.affected);
    println!("Packages Altered:\n    {} {}", entry.action, affected.join(" "))
}

fn list(args: Args) {
    let mut entries = history_entries();

    // Default behavior is to list entries in descending order by ID.
    if !args.reverse {
        entries.reverse();
    }

    let mut rows: Vec<Vec<Cell>> = Vec::new();
    entries.iter().for_each(|entry| {
        let row = vec![
            Cell::Int(entry.id as i32),
            Cell::from(&entry.command_line),
            Cell::from(&entry.start_date),
            Cell::from(&entry.action),
            Cell::Int(entry.altered as i32),
        ];
        rows.push(row);
    });

    let table = Table::new(Style::Presto, rows,
                           Some(Headers::from(HEADERS.to_vec()))).tabulate();
    println!("{}", table);
}

fn history(args: Args) {
    match args.command.as_str() {
        "list" => list(args),
        "info" => info(args),
        _ => panic!("unknown command: `{}`", args.command),
    }
}

fn main() {
    let args = Args::parse();
    history(args);
}