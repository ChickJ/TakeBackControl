# Take Back Control #

I am tired of software vendors with the attitude that my computer is theirs
to with as they please. Every time some piece of software auto-updates it
undoes my work. Some examples include:

* NVIDIA desktop context menus
* Skype desktop icon restoration
* Windows enabling services

It is time to take back control and that is what this project helps me do.

Take back control is a Powershell script that modifies a bunch of stuff on
the computer returning it to my preferences, not someone elses. The script
runs as an Administrator and has the following capabilities:

* Change File Explorer preferences and behavior
* Change power management settings
* Change registry settings
* Change Start menu settings
* Change system pagefile settings
* Clear event logs
* Delete files off the desktop
* Disable scheduled tasks
* Disable system services
* Permanently remove Windows Store apps
* Remove right-click context menus

Run the script manually
```
U:\Projects\Take Back Control> .\TakeBackControl.ps1 -now
```

Or run it as a scheduled task
```
C:\Program Files> .\TakeBackControl.ps1
```

> I'm not a big Powershell fan, but it's installed out of the box, has no
> dependencies and does want I want. The script is documented, is easy to
> change. Most importantly you can see exactly what it does unlike other
> system cleaners. Feel free to use the script however you want. I'm happy
> if someone else finds it useful.
