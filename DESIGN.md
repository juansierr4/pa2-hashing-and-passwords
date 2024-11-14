How many password variations were hashed and tested for a match?
"secret118": 25 hashes (1 base + 6 case changes + 2 digits x 9 variations)
"secret111": 34 hashes (1 base + 6 case changes + 3 digits x 9 variations)
59 total

How many duplicate password variations were hashed and checked?
Case variations were computed twice (6 duplicates) and some digit variations overlap like testing "secret110 for both inputs.

What are ways you might change your implementation to avoid this repeated and redundant work?
In check_password(), I allocate a new hash buffer every time, instead, I could pass in a pre-allocated buffer and reuse it for all hash computations in the function. There is also unnecessary string copies on each iteration when I call strcp(current, orignal); and then I compute the hash again in the main() function. I could modify the functions to pass the computed hash by passing a pointer in the check_password()n function.