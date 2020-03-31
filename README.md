# cryptopals

These are my solutions to the Cryptopals Challenges. They are written in Python 3.

I've had so much fun working through these over the last few months that I can't resist sharing my results. I've tried to make them as readable as possible.

That said, if you're working through these challenges yourself, try to resist spending too much time looking at other people's work - you learn more when you figure the problems out for yourself!

If you're interested in this stuff, feel free to hit me up [on Twitter](https://twitter.com/elisohl) or [elsewhere](https://eli.sohl.com/contact).


# Requirements

Some of these scripts require Python 3.6+, mostly just because I like to use f-strings for complex outputs.

There are a few library dependencies as well:

* `pycrypto` to get native-C implementations of some primitives (mostly AES). Whenever a crypto algorithm's internals are the focus of a challenge, I use custom-written, native Python implementations; the rest of the time, I prefer to use these versions because they run much faster.
* `flask` for challenges 31 and 32, which involve timing attacks carried out over HTTP.
* `sympy` for challenges 40 and 42, where I wanted to calculate bignum cube roots without using floating point numbers. You could argue that pulling in a library for this is overkill, and you'd probably be right, but it gets the job done.


# Running

Almost all of these scripts are stand-alone and noninteractive, i.e. you can just start them with `python3 challenge_xx.py` and watch them run.

The only two exceptions are challenges 31 and 32, which require a standalone web server to connect to. On startup they will prompt you for a server URL. The correct server invocations are documented at the top of `challenge_31_server.py` and `challenge_32_server.py`.

The challenges are named so that lexographic ordering preserves challenge order, meaning you can run them all in order from the command line with something like this:

`for fname in *.py; do echo "========== running $fname =========="; python3 $fname; done`

This will allow you to loop through all the challenges in order. You will be able to skip individual challenges at will with Ctrl-C, which is useful for the few scripts that run forever (52, 55) as well as for those that just take a very long time to run (e.g. 31, 32, 56).


# Reading

There are a few style conventions I've followed to make these scripts easier to read.

All custom functions have type annotations. Some crypto primitives (e.g. hash functions, block ciphers) represent messages as bytestrings, whereas other primitives (e.g. RSA) represent messages as very large integers; still other functions (e.g. the oracle in challenge 51) might deal natively with `str`s. Type annotations provide implicit documentation for how we're representing messages in any given challenge.

Many of these challenges involve setting global values that are meant to be unknown to the attacker. To sharpen the distinction between known values (like an IV) and secret values (like a key), every time a value is meant to be secret but is technically within scope of the attacking code I've prefixed it with a single underscore, like `_key`. This makes it easy to confirm at a glance that the attack code doesn't touch these values.

I do occasionally throw PEP-8 out the window, most notably in my MD5 implementation (challenge 30). This is only ever done when I think it improves readability. I understand that some might still find it disturbing, but I would remind those people that (in Guido's words) _a foolish consistency is the hobgoblin of little minds._ In other words, part of knowing the rules is knowing when and how to break them.

I think that just about covers it. Thanks for reading, and if you like what you see here, drop me a line :)
