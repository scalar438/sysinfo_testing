extern crate sysinfo;
use sysinfo::ProcessExt;

fn main() -> std::io::Result<()> {
	let mut input = String::new();
	loop {
		input.clear();
		println!("Enter pid (0 if you want to exit):");
		std::io::stdin().read_line(&mut input)?;
		let pid;
		match input.trim().parse::<sysinfo::Pid>() {
			Ok(r) => pid = r,
			Err(_) => 
			{
				println!("Sorry, try again.");
				continue;
			}
		}
		if pid == 0
		{
			break;
		}

		let p = sysinfo::Process::new(pid, None, 0);
		println!("Process cmdline with pid = {:} is {:?}", pid, p.cmd());
	}

	Ok(())
}
