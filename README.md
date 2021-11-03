# SMB35
A custom server for Super Mario Bros. 35

To try it out, simply copy the patch folder into `/atmosphere/exefs_patches` and play the game. The patch redirects the game to `smb35.ymar.dev:20000`, which is where I am hosting the game server. It also disables all prepo and most bcat calls that are made by the game.

The dashboard is hosted at https://smb35.ymar.dev:20002. Here you can check out if anyone is currently playing the game.

If you encounter any bugs, please submit an [issue](https://github.com/kinnay/SMB35/issues) or [pull request](https://github.com/kinnay/SMB35/pulls) on github.

### Installation
In order to self-host the server, the following requirements must be met:
- A TLS certificate in the form of a fullchain.pem and a privkey.pem

1. Install project's dependencies
``` bash
pip install -r requirements.txt
```
2. Create a `resources/` folder on `./source/`
3. Move your `fullchain.pem` and your `privkey.pem` to `./sources/resources`
4. Launch the server `python main.py`

5. In order for the patch to redirect to your own domain, you should edit said patch file. The easiest way to do this would be with an hex editor. At offset `0x35` the URL starts. Replace it with your own. In the event that your URL has a different length than the original, you should change said length in `0x33-0x34`. You should write your length+1 in that offset. Do not forget to leave a null byte(`0x00`) between the URL and EEOF
6. You should also change the URL in [main.py](https://github.com/kinnay/SMB35/blob/master/source/main.py#L196) to reflect your own. Check [#1](https://github.com/kinnay/SMB35/issues/1) for more info

### Links
* [Python package for game servers](https://github.com/kinnay/NintendoClients)
* [Documentation about game servers](https://github.com/kinnay/NintendoClients/wiki)
* [Documentation about the relay server](https://github.com/kinnay/NintendoClients/wiki/Eagle-Protocol)
