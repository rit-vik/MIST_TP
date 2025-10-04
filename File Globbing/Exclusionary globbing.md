# Exclusionary globbing

Adding a "!" will match all the files which do not match the followed argument. (Similar to !=)
"!" has now been changed to "^" in newer version of shells

```bash
hacker@globbing~exclusionary-globbing:~$ cd /challenge/files
hacker@globbing~exclusionary-globbing:/challenge/files$ /challenge/run [!pwn]*
You got it! Here is your flag!
pwn.college{Imv0sR638XjBVNPeLlVWUJNci-f.dZjM4QDL0czM2czW}
```

The resources used were
1)Ubuntu 22.04.5 LTS
2)pwn.college
