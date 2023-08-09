# snowcra5h@icloud.com
#
# Display a list of files available for download 
# from your hosted web server. These files should 
# have already existed locally using the generate_files.sh 
# bash script, which creates the files.txt document 
# that gets parsed. Select the files you want 
# for the current session, which will download 
# to the current user's desktop. 
# 
# snowcrash - OSED 2022

Invoke-Expression "Set-ExecutionPolicy Unrestricted"

$webClient = New-Object System.Net.WebClient
$webClient.DownloadString("http://192.168.49.165:9000/files.txt")

$files = @()
$continue = $true
while (1) {
	$file = Read-Host "Enter a file to download type download when finished"
	if ($file -eq "download") {
		break
	}
	Write-Host "   [ $files ]"
	Write-Host " + $file"
	$files += $file
}
foreach ($file in $files) {
	$webClient.DownloadFile("http://192.168.49.165:9000/$file", "C:\Users\Offsec\Desktop\$file")
}
