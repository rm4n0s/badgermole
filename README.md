# Badgermole

Badgermole is a library for creating an SSH App server for OTP (One Time Passwords) for authenticating requests to HTTP server. <br/>
This library exists because username/password are unsafe in this day and age, while other OTP mechanics have become complicating.

## Install

```bash
go get github.com/rm4n0s/badgermole
```


## How to use
There is an example in 'examples/simple' which is a web server that allows the user to sign up with the SSH public key and login with the OTP from SSH.
```bash
# 1) build the example
cd examples/simple
go build

# 2) visit the home page
firefox localhost:3000

# 3) copy the public key
cat ~/.ssh/your_public_key  

# 4) visit localhost:3000/signup and add a name and the key

# 5) copy the OTP from SSH 
ssh -i ~/.ssh/your_private_key -p 10000 localhost
# If you have signed up correctly then you will see something like One Time Password = <uuid>
# You can also get the OTP in a json format if you put "json" at the end of the command line

# 6) visit localhost:3000/login and submit the One Time Password before a minute pass.
# now a cookie is created that shows you are authorized

```

This is just a preview

```go
import	"github.com/rm4n0s/badgermole"

func main(){
	cfg := &badgermole.Config{
		SshHost:     "localhost:3000",
		SshKeyPath:  "sshkeys/somekey", // if it does not exist, then it will create it automatically
		SshAuthFunc: func(ctx ssh.Context, key ssh.PublicKey) bool { 
            // authenticate key and return true if it is authorized to receive OTP" 
            return true
        },
		Store:       badgermole.NewMemoryStore(), // you can create your own DB for OTP as long as it implements IStore interface 
	}

    bmSrv, err := badgermole.NewServer(cfg)
	if err != nil {
		log.Fatal("Error:", err)
	}

	err := bmSrv.Start()
	if err != nil {
		log.Fatal("Error:", err)
	}
}



```


