#python $combinePath -p C4B1B5D0 userdata.bin
#Get Current Working Directory 
#split-path is used to get the path UP TO the ps1 name
$CWD = Split-Path $MyInvocation.MyCommand.Path -Parent
#combine path is used to safely and correctly concatenate CWD and name of the python script
$combinePath = Join-Path $CWD "searchbin.exe"
#this lets powershell know that the following is a executable that should be run with args
#-p sets the flag to run a hex search
#If the F2F2F2F2 is the hex signature we are looking for and if the file to be searched is called
#metadata.bin then
Start-Process -FilePath $combinePath -ArgumentList "-p F2F2F2F2 metadata.bin"