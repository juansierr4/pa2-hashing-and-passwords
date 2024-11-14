I used https://security.stackexchange.com/questions/139906/are-leet-passwords-easily-crackable to find that "leet speak" substitutions lke turning 'a' to '@' or 'o' to '0' are predictable. Mkaing them easier for password crackers to include in their guess patterns.

I asked chat-gpt 4o what is wrong with this code? and it was a simple [1] replaced with [i] in this line
original[i] = password[1]; -> password[i] = original[i];