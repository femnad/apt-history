use std::fs::File;
use std::io;
use std::io::BufRead;
use std::ops::Add;

use clap::Parser;
use stybulate::{Cell, Headers, Style, Table};

const APT_HISTORY_LOG: &str = "/var/log/apt/history.log";
const MAX_COMMAND_LINE_LEN: usize = 100;
const COMMAND_LINE_ELLIPSIS: &str = " <...>";

#[derive(Clone)]
struct HistoryEntry {
    action: String,
    affected: String,
    command_line: String,
    end_date: String,
    start_date: String,
    id: u32,
}

impl Default for HistoryEntry {
    fn default() -> Self {
        HistoryEntry {
            action: "".to_string(),
            affected: "".to_string(),
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
}

fn history(args: Args) -> io::Result<()> {
    let log = File::open(APT_HISTORY_LOG)?;
    let reader = io::BufReader::new(log);

    let mut rows: Vec<Vec<Cell>> = Vec::new();

    let mut seen_entry = false;
    let mut index = 1;

    let mut entry = HistoryEntry { ..Default::default() };

    for line in reader.lines() {
        let line = line?;

        if line.is_empty() {
            if !seen_entry {
                seen_entry = true;
                continue;
            }

            entry.id = index;

            let mut command_line = entry.command_line.clone();
            if command_line.len() > MAX_COMMAND_LINE_LEN {
                command_line = command_line[0..MAX_COMMAND_LINE_LEN - COMMAND_LINE_ELLIPSIS.len()].to_string().add(COMMAND_LINE_ELLIPSIS);
            }
            if command_line.starts_with("apt ") {
                command_line = command_line[4..].to_string();
            }

            let altered = entry.affected.match_indices("),").count() + 1;

            let row = vec![
                Cell::Int(index as i32),
                Cell::from(&command_line),
                Cell::from(&entry.start_date),
                Cell::from(&entry.action),
                Cell::Int(altered as i32),
            ];
            rows.push(row);
            index += 1;
            entry = HistoryEntry { ..Default::default() };
            continue;
        }

        let mut fields = line.split(": ");
        let descriptor = fields.nth(0).unwrap();
        let value = fields.last().expect(format!("error processing line `{}`", line).as_str());

        match descriptor {
            "Commandline" => entry.command_line = value.to_string(),
            "End-Date" => entry.end_date = value.to_string(),
            "Start-Date" => entry.start_date = value.to_string(),
            "Install" | "Purge" | "Remove" | "Upgrade" => {
                entry.action = descriptor.to_string();
                if entry.affected.is_empty() {
                    entry.affected = value.to_string();
                } else {
                    entry.affected = format!(" {}", entry.affected)
                }
            }
            "Error" | "Requested-By" => {}
            _ => panic!("unknown field {}", descriptor)
        }
    }

    // Default behavior is to list entries in descending order by ID.
    if !args.reverse {
        rows.reverse();
    }

    let result = Table::new(
        Style::Presto,
        rows,
        Some(Headers::from(vec!["ID", "Command line", "Date and time", "Action(s)", "Altered"])),
    ).tabulate();
    println!("{}", result);

    Ok(())
}

fn main() {
    let args = Args::parse();
    if let Err(e) = history(args) {
        eprintln!("{}", e);
    }
}
