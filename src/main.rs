mod history;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    reverse: bool,

    #[arg(default_value = "list")]
    command: String,

    id: Option<u32>,
}

fn history(args: Args) {
    match args.command.as_str() {
        "list" => history::list(args.reverse),
        "info" => history::info(args.id),
        _ => panic!("unknown command: `{}`", args.command),
    }
}

fn main() {
    let args = Args::parse();
    history(args);
}
