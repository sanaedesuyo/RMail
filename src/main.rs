use clap::Parser;

fn main() {
    let cli = RMail::cli::Cli::parse();
    if let Err(error) = RMail::cli::run(cli) {
        eprintln!("错误：{error}");
        std::process::exit(1);
    }
}
