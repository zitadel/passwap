package testvalues

// Firebase scrypt test values generated with firebasescrypt.py.
// The parameters are the sample from https://github.com/firebase/scrypt.
const (
	FirebaseScryptPassword      = "user1password"
	FirebaseScryptSalt          = "42xEC+ixf3L2lw=="
	FirebaseScryptHash          = "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ=="
	FirebaseScryptSaltSeparator = "Bw=="
	FirebaseScryptSignerKey     = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="

	FirebaseScryptEncoded                = `$firebasescrypt$ln=14,r=8$42xEC+ixf3L2lw==$lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==$Bw==$jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==`
	FirebaseScryptEncodedNoSaltSeparator = `$firebasescrypt$ln=14,r=8$42xEC+ixf3L2lw==$NohHtJ2FmkEqzefZ0IHnOlqTzFN8n6vXXd0EW2OIGuUh4rcwvVh7XVRDVs5yOrueoudRPIoimS6jIwf4pMW3rg==$$jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==`
	FirebaseScryptEncodedLowCost         = `$firebasescrypt$ln=10,r=4$42xEC+ixf3L2lw==$EQ0tlNdKv5ZBDYN7ofOYlhhTEe5Tu9bueDmtDUhLPM+9dcS1u1ALgMcT6N1+U9GsDlVdd3FE2dmz37fU5Y8A9Q==$Bw==$jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==`
)
