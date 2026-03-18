# 0ctf2025 Motion Blur

It is rumored that blurring sensitive information is unsafe...

Flag format: `0ctf{.*}`

[Attachment](flag.webp)

If you cannot see the last part clearly, here's the hint: it is a meaningful word encoded in hex

## Notes

Inspired by https://www.youtube.com/watch?v=acKYYwcxpGk

Credits to https://github.com/KoKuToru/de-pixelate_gaV-O6NPWrI/blob/master/example/mosaic-area.ipynb



Just changed a few params in the original notebook, input a fresh photo with flag, and you get this challenge.

Some teams tried solving this challenge by directly sending the picture to a vision language model, and obviously it did not work...

It is not so hard to determine the type of mosaic (area filter), the boundaries and the size of the blurring blocks. (You may observe the pixels carefully to fin)

I'm sorry for the guesses of chars but the original photo have to be with this amount of artifacts, or it might be too easy to solve. An ideal solution should get a clear enough view to recognize the flag with the given hint.



Flag: `0ctf{m@ster_Mosaic_6d6f73616963}`