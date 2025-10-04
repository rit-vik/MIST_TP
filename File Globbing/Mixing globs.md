# Mixing globs

These matching can be interlinked as well. Like []* or []? or ?[] and *[]

```bash
hacker@globbing~mixing-globs:~$ cd /challenge/files
hacker@globbing~mixing-globs:/challenge/files$ ls [cep]*
challenging  educational  pwning
hacker@globbing~mixing-globs:/challenge/files$ /challenge/run [cep]*
You got it! Here is your flag!
pwn.college{I644ouHMOXK2QcQWRkP8D10spPP.dVjM4QDL0czM2czW}
```
The resources used were
1)Ubuntu 22.04.5 LTS
2)pwn.college
