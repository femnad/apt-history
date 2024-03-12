use ansi_term;
use chrono::prelude::*;
use flate2::read::GzDecoder;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufRead;
use std::ops::Add;
use std::path::PathBuf;
use std::{fs, io};
use std::cmp::Ordering;
use stybulate::{Cell, Headers, Style, Table};

const APT_LOG_PATH: &str = "/var/log/apt";
const APT_HISTORY_LOG_PATTERN: &str = r"history\.log(\.[0-9]+\.gz)?";
const COMMAND_LINE_ELLIPSIS: &str = " <...>";
const CURRENT_HISTORY_FILE: &str = "history.log";
const HEADERS: [&str; 5] = [
    "ID",
    "Command line",
    "Date and time",
    "Action(s)",
    "Altered",
];
const SEPARATOR_CHAR: char = '-';
const SEPARATOR_LENGTH: usize = 79;
const INFO_DATE_FORMAT: &str = "%a %b %e %T %Y";
const LIST_DATE_FORMAT: &str = "%F %H:%M";
const LOG_FILE_DATE_FORMAT: &str = "%F  %T";
const MAX_COMMAND_LINE_LEN: usize = 100;

#[derive(Clone)]
struct HistoryEntry {
    affected: HashMap<String, HashMap<String, HashSet<String>>>,
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
            affected: HashMap::new(),
            altered: 0,
            command_line: "".to_string(),
            end_date: Local::now().naive_local(),
            id: 0,
            start_date: Local::now().naive_local(),
        }
    }
}

fn finalize_entry(
    entry: &mut HistoryEntry,
    index: u32,
    package_map: &HashMap<String, HashMap<String, HashSet<String>>>,
) {
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
    for packages in package_map.values() {
        for pkgs in packages.values() {
            altered += pkgs.len();
        }
    }
    entry.altered = altered;
    entry.affected = package_map.clone();
}

fn add_parsed_package(
    packages: &HashMap<String, HashSet<String>>,
    package: String,
) -> HashMap<String, HashSet<String>> {
    let fields: Vec<&str> = package.split(":").collect();
    let name = fields.get(0).expect("Unable to parse package name");
    let arch = fields.get(1).expect("Unable to parse package architecture");

    let mut packages = packages.clone();
    if packages.contains_key(&arch.to_string()) {
        packages
            .get_mut(&arch.to_string())
            .expect("Unable to update package map")
            .insert(name.to_string());
    } else {
        let mut package_set = HashSet::new();
        package_set.insert(name.to_string());
        packages.insert(arch.to_string(), package_set);
    }
    return packages;
}

fn packages_from_action_line(line: String) -> HashMap<String, HashSet<String>> {
    let mut packages: HashMap<String, HashSet<String>> = HashMap::new();
    let mut package = String::new();
    let mut inside_parens = false;

    for c in line.chars() {
        match c {
            ' ' => (),
            '(' => inside_parens = true,
            ')' => inside_parens = false,
            ',' => {
                if !inside_parens {
                    packages = add_parsed_package(&packages, package);
                    package = String::new();
                }
            }
            _ => {
                if !inside_parens {
                    package.push(c)
                }
            }
        }
    }

    // Line does not end with a comma.
    packages = add_parsed_package(&packages, package);
    return packages;
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
    let mut package_map: HashMap<String, HashMap<String, HashSet<String>>> = HashMap::new();

    for line in reader.lines() {
        let line = line.unwrap();

        if line.is_empty() {
            if !seen_entry {
                seen_entry = true;
                continue;
            }

            finalize_entry(&mut entry, index, &package_map);
            package_map.clear();
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
                package_map.insert(
                    descriptor.to_string(),
                    packages_from_action_line(value.to_string()),
                );
            }
            "Error" | "Requested-By" => {}
            _ => panic!("unknown field {}", descriptor),
        }
    }

    // Check if this was an empty log file
    if !entry.command_line.is_empty() {
        // Last line is not empty.
        finalize_entry(&mut entry, index, &package_map);
        entries.push(entry);
    }
    entries
}

fn path_buf_name(p: &PathBuf) -> &str {
    p.file_name().expect("error getting file name").to_str() .expect("error converting file name")
}

fn log_file_num(f: &str) -> u32 {
    let fields: Vec<&str> = f.split(".").collect();
    let num_field = fields.get(2).expect("Unable to find number field in log file name");
    let number: u32 = num_field.parse().expect("Unable to parse log file number");
    number
}

fn sort_log_files(a: &PathBuf, b: &PathBuf) -> Ordering {
    let a_name = path_buf_name(a);
    let b_name = path_buf_name(b);

    if a_name == CURRENT_HISTORY_FILE {
        return Ordering::Greater
    }
    if b_name == CURRENT_HISTORY_FILE {
        return Ordering::Less
    }

    let a_num = log_file_num(a_name);
    let b_num = log_file_num(b_name);
    // Older log files have smaller number suffixes.
    a_num.cmp(&b_num).reverse()
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
    history_files.sort_by(sort_log_files);

    let mut combined: Vec<HistoryEntry> = vec![];
    let mut id: u32 = 1;
    for file in history_files {
        let entries = entries_from_file(file.to_str().expect("error getting file path"), id);
        if entries.len() == 0 {
            continue;
        }
        let num_entries = entries.len() as u32;
        combined.extend(entries);
        id += num_entries;
    }

    combined
}

fn show_transaction(entry: &HistoryEntry) {
    let duration = entry.end_date - entry.start_date;
    let end_time = format!(
        "{} ({} seconds)",
        entry.end_date.format(INFO_DATE_FORMAT),
        duration.num_seconds()
    );

    let mut header_table = tabular::Table::new("{:<} : {:<}");
    header_table.add_row(
        tabular::Row::new()
            .with_cell("Transaction ID")
            .with_cell(entry.id),
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
    let mut actions: Vec<&String> = entry.affected.keys().clone().collect();
    actions.sort();

    let style = ansi_term::Style::new().bold();
    for action in actions {
        let pkg_map: &HashMap<String, HashSet<String>> = entry
            .affected
            .get(action.as_str())
            .expect("unexpected entry miss in map");

        let mut pkgs: Vec<String> = Vec::new();
        for (arch, pkg_list) in pkg_map.iter() {
            for pkg in pkg_list {
                pkgs.push(format!("{pkg}:{arch}"))
            }
        }
        pkgs.sort();

        for pkg in pkgs {
            pkgs_table.add_row(
                tabular::Row::new()
                    .with_cell(style.paint(action))
                    .with_cell(pkg),
            );
        }
    }

    print!("{pkgs_table}");
}

fn matches(entry: &HistoryEntry, ids: &HashSet<u32>, packages: &HashSet<String>) -> bool {
    if ids.contains(&entry.id) {
        return true;
    }

    for affected in entry.affected.values() {
        for pkgs in affected.values() {
            let union: HashSet<&String> = packages.intersection(pkgs).collect();
            if union.len() > 0 {
                return true;
            }
        }
    }

    false
}

fn matching_entries(query: Option<Vec<String>>) -> Vec<HistoryEntry> {
    let entries = history_entries();
    let max_id = entries.len() as u32;
    let fallback_transaction: String = max_id.to_string();

    let transactions = query.clone()
        .or(Some(vec![fallback_transaction]))
        .expect("error getting ID of history entry");

    let mut ids: HashSet<u32> = HashSet::new();
    let mut packages: HashSet<String> = HashSet::new();
    for transaction in transactions {
        match transaction.parse::<i32>() {
            Ok(mut tid) => {
                if tid <= 0 {
                    tid = (max_id as i32) + tid;
                }
                ids.insert(tid as u32)
            },
            Err(_) => packages.insert(transaction),
        };
    }

    return entries
        .iter()
        .filter(|e| matches(e, &ids, &packages))
        .cloned()
        .collect();
}

pub fn info(query: Option<Vec<String>>) {
    let selected = matching_entries(query);

    let separator = SEPARATOR_CHAR.to_string().repeat(SEPARATOR_LENGTH);
    for (index, entry) in selected.iter().enumerate() {
        if index > 0 {
            println!("{separator}")
        }
        show_transaction(entry)
    }
}

pub fn list(query: Option<Vec<String>>, reverse: bool) {
    let mut selected = if query.is_some() {
        matching_entries(query)
    } else {
        history_entries()
    };

    // Default behavior of dnf is to list entries in descending order by ID, the entries we get by
    // parsing history logs is in ascending order by default.
    if !reverse {
        selected.reverse();
    }

    let mut rows: Vec<Vec<Cell>> = Vec::new();
    selected.iter().for_each(|entry| {
        let actions: Vec<&String> = entry.affected.keys().collect();
        let actions = if actions.len() == 1 {
            actions
                .get(0)
                .expect("error getting action of history entry")
                .to_string()
        } else {
            let mut initials: Vec<_> = actions
                .iter()
                .map(|a| {
                    a.chars()
                        .nth(0)
                        .expect("error getting first char of action")
                        .to_string()
                })
                .collect();
            initials.sort();
            let joined = initials.join(", ");
            joined
        };

        let row = vec![
            Cell::Int(entry.id as i32),
            Cell::from(&entry.command_line),
            Cell::from(&entry.start_date.format(LIST_DATE_FORMAT).to_string()),
            Cell::from(&actions),
            Cell::Int(entry.altered as i32),
        ];
        rows.push(row);
    });

    let table = Table::new(Style::Presto, rows, Some(Headers::from(HEADERS.to_vec()))).tabulate();
    println!("{}", table);
}
