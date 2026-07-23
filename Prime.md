### Exploit To-Do:
#### Phase 1
- [ ] add root ssh key
- [ ] remove `ubnt`/`ubnt` or whatever the original password/creds are and replace it with something else 
#### Phase 2
- [ ] Do the fun video walll stuff as PoC
	- [ ] host the video as a low priv user
- [ ] Mitigate LFI

---
![[Projects/attachments/2026-06-29_22-15.png]]
image: the router accepted the modded tarball
	lessons learned:
	1. check for md5 hash at every step of transfer from attack machine to router
	2. make sure the owner of the contents of the tarball is `root/root`


![[Pasted image 20260722212133.png]]
image: permitrootlogin value does not persist in the live image (yes -> no)


---

### What have I done so far:
