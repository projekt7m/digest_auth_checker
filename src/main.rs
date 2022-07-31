use clap::Parser;
use console::style;

/// Simple program to verify a SIP digest authentication handshake
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, value_parser)]
    username: String,

    #[clap(short, long, value_parser)]
    realm: String,

    #[clap(short, long, value_parser)]
    password: String,

    #[clap(short, long, value_parser)]
    nonce: String,

    /// Method of the request (default: INVITE)
    #[clap(short, long, value_parser)]
    method: Option<String>,

    /// Request URI
    #[clap(long, value_parser)]
    uri: String,
}

fn hash_string(input: &str) -> String {
    let bytes = input.as_bytes();
    let digest = md5::compute(bytes);
    format!("{:x}", digest)
}

fn main() {
    let args = Args::parse();

    println!(
        "Used calculation: {} {}",
        style("RFC 2069").blue(),
        style("(qop not present)").white()
    );
    println!("Used algorith: {}", style("MD5").blue());
    println!("");

    let a1 = format!("{}:{}:{}", args.username, args.realm, args.password);
    println!("{}", style("A1:").green());
    println!("  {}", style("username:realm:password").white());
    println!("  {}", a1);

    let method = args.method.unwrap_or("INVITE".to_string()).to_uppercase();
    let a2 = format!("{}:{}", method, args.uri);
    println!("{}", style("A2:").green());
    println!("  {}", style("method:uri").white());
    println!("  {}", a2);

    let ha1 = hash_string(&a1);
    let ha2 = hash_string(&a2);

    println!("{}", style("HA1:").green());
    println!("  {}", style("md5_hex(A1)").white());
    println!("  {}", ha1);
    println!("{}", style("HA2:").green());
    println!("  {}", style("md5_hex(A2)").white());
    println!("  {}", ha2);

    let response = format!("{}:{}:{}", ha1, args.nonce, ha2);
    let response_digest = hash_string(&response);

    println!("{}", style("clear response:").green());
    println!("  {}", style("HA1:nonce:HA2").white());
    println!("  {}", response);

    println!("{}", style("response digest:").green());
    println!("  {}", style("md5_hex(clear response)").white());
    println!("  {}", response_digest);
}
