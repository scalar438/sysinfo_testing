extern crate sysinfo;
use sysinfo::ProcessExt;

fn main() {
	let mut input = String::new();
	std::io::stdin().read_line(&mut input).unwrap();
	print!("{}", sysinfo::Process::new(input.trim().parse().unwrap(), None, 0).cmd().join(" "));
	std::thread::sleep(std::time::Duration::from_secs(1));
}
