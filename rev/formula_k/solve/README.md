To solve the challenge players should discover a way to decompile/decode the handout `formula_k.uf2` file. The easiest way is to use the online [Makecode Lego Tool](https://makecode.mindstorms.com/). The big array in the beginning of this file is extracted and put into the `uf2.json`

Now make sure `ffmpeg` is installed on your system. Then run:

```
pip install -r requirements.txt
```

Run

```
python solve.py
```

Result will be in the `results` directory
