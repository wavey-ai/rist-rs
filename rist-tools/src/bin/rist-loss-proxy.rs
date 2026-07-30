use rist_tools::{LossProxy, LossProxyConfig};
use serde::Serialize;
use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Args {
    listen: SocketAddr,
    upstream_bind: SocketAddr,
    target: SocketAddr,
    drop_every: u64,
    duration: Option<Duration>,
    stats_interval: Duration,
}

#[derive(Serialize)]
struct StatsLine {
    elapsed_ms: u128,
    listen: SocketAddr,
    upstream: SocketAddr,
    target: SocketAddr,
    drop_every: u64,
    #[serde(flatten)]
    stats: rist_tools::LossProxyStats,
}

fn main() -> ExitCode {
    match run() {
        Ok(complete) if complete => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(error) => {
            eprintln!("rist-loss-proxy: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let args = parse_args(env::args().skip(1))?;
    let mut proxy = LossProxy::bind(LossProxyConfig {
        listen: args.listen,
        upstream_bind: args.upstream_bind,
        target: args.target,
        drop_every: args.drop_every,
    })?;
    let listen = proxy.listen_addr()?;
    let upstream = proxy.upstream_addr()?;
    let started = Instant::now();
    let deadline = args.duration.map(|duration| started + duration);
    let mut next_stats = started;

    loop {
        let processed = proxy.poll()?;
        let now = Instant::now();
        if now >= next_stats {
            print_stats(
                &proxy,
                started,
                listen,
                upstream,
                args.target,
                args.drop_every,
            )?;
            next_stats = now + args.stats_interval;
        }
        if deadline.is_some_and(|deadline| now >= deadline) {
            let stats = proxy.stats();
            print_stats(
                &proxy,
                started,
                listen,
                upstream,
                args.target,
                args.drop_every,
            )?;
            return Ok(args.drop_every == 0 || stats.all_injected_drops_recovered());
        }
        if processed == 0 {
            thread::sleep(Duration::from_micros(100));
        }
    }
}

fn print_stats(
    proxy: &LossProxy,
    started: Instant,
    listen: SocketAddr,
    upstream: SocketAddr,
    target: SocketAddr,
    drop_every: u64,
) -> Result<(), serde_json::Error> {
    println!(
        "{}",
        serde_json::to_string(&StatsLine {
            elapsed_ms: started.elapsed().as_millis(),
            listen,
            upstream,
            target,
            drop_every,
            stats: proxy.stats(),
        })?
    );
    Ok(())
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> io::Result<Args> {
    let mut listen = None;
    let mut upstream_bind = None;
    let mut target = None;
    let mut drop_every = 0;
    let mut duration = None;
    let mut stats_interval = Duration::from_secs(1);
    let mut arguments = arguments.into_iter();

    while let Some(argument) = arguments.next() {
        let value = match argument.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--listen"
            | "--upstream-bind"
            | "--target"
            | "--drop-every"
            | "--duration-seconds"
            | "--stats-interval-ms" => arguments.next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{argument} requires a value"),
                )
            })?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {argument}"),
                ));
            }
        };
        match argument.as_str() {
            "--listen" => listen = Some(parse_socket_addr("--listen", &value)?),
            "--upstream-bind" => {
                upstream_bind = Some(parse_socket_addr("--upstream-bind", &value)?)
            }
            "--target" => target = Some(parse_socket_addr("--target", &value)?),
            "--drop-every" => drop_every = parse_u64("--drop-every", &value)?,
            "--duration-seconds" => {
                duration = Some(Duration::from_secs(parse_positive_u64(
                    "--duration-seconds",
                    &value,
                )?))
            }
            "--stats-interval-ms" => {
                stats_interval =
                    Duration::from_millis(parse_positive_u64("--stats-interval-ms", &value)?)
            }
            _ => unreachable!(),
        }
    }

    let listen = listen
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--listen is required"))?;
    let target = target
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--target is required"))?;
    let unspecified = match target.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    Ok(Args {
        listen,
        upstream_bind: upstream_bind.unwrap_or(SocketAddr::new(unspecified, 0)),
        target,
        drop_every,
        duration,
        stats_interval,
    })
}

fn parse_socket_addr(name: &str, value: &str) -> io::Result<SocketAddr> {
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a numeric socket address: {error}"),
        )
    })
}

fn parse_u64(name: &str, value: &str) -> io::Result<u64> {
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be an unsigned integer: {error}"),
        )
    })
}

fn parse_positive_u64(name: &str, value: &str) -> io::Result<u64> {
    let parsed = parse_u64(name, value)?;
    if parsed == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be greater than zero"),
        ))
    } else {
        Ok(parsed)
    }
}

fn print_help() {
    println!(
        "Usage: rist-loss-proxy --listen ADDR --target ADDR [OPTIONS]\n\
         \n\
         Options:\n\
           --upstream-bind ADDR       Receiver-facing local address\n\
           --drop-every N             Drop every Nth first media transmission\n\
           --duration-seconds N       Exit after N seconds\n\
           --stats-interval-ms N      NDJSON statistics interval (default: 1000)"
    );
}
