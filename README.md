# Astaroth-string-decrypt
Ida python script for automating string decryption of Astaroth/Guildma samples. All the heavy lifting is done by [AstaGuilStringSlayer](https://github.com/Xienim/AstaGuilStringSlayer) from Xienim; all I did was force Ida to set the encrypted strings correctly, then grab the output from Xienim's script and set it as comments next to the line of code where that encrypted string is moved to `EAX`. This is the result:
 
[Demo screenshot](Capture.PNG)
 
# TODO
For now the decryptrion key must be supplied by the user when prompted by the script. I plan on recovering that automatically in the near future.