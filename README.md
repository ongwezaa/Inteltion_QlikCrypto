# Inteltion_QlikCrypto

Description: Encryption(AES-256) process with C programm as addon in Qlik Replicate.

***** Source code and library is not completed development and testing. (Work in Progress) *****

Included library: 
1. OpenSSL
2. Curl

Source code: at path "addons\samples\MyTransformation"

We modified code from sample code of Qlik Replicate and use default name as "MyTransformation". You can open solution file at addons\samples\MyTransformation\MyTransformation.sln.

Source code description:

1. Properties
- Additional include directories: include path of program is at "addons\include"

![Untitled](https://user-images.githubusercontent.com/54891949/128844489-7f92db5d-9192-48e2-9eba-5d11ccad6cbe.jpg)

- Additional dependencies: static library which we mention in above part is at "addons\lib"

![2](https://user-images.githubusercontent.com/54891949/128844510-870a8bf8-78c1-49b0-8565-8e213a8a39b5.jpg)

2. Main function
- ar_addon_init: used for initialize and register function in Qlik Replicate console as user defined function in transform tab.

![11](https://user-images.githubusercontent.com/54891949/130902148-90575703-41d4-446c-873d-557d569fc3b7.jpg)

This function call method "auth_plt_gen_key" in the end which is process for retrieve key vault from Azure key vault through managed identity and keep key in memory of Qlik addon pool.

Reference link from Azure tu use managed identity to access key vault 
https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/tutorial-windows-vm-access-nonaad

All variable is defined at top of file
![22](https://user-images.githubusercontent.com/54891949/130902625-bfc113fe-f42a-4056-b356-49fce3e2d9e3.jpg)


- encrypt_aes: main encryption function called from Qlik Replicate. Flow of this function as below.
> 1) Starting with get key from text file which was generated from above function.

> 2) Call OpenSSL library to encrypt string from argument.

> 3) Encode encrypted text to base 64.

> 4) Return encoded text to Qlik Replicate.

3. Build DLL: configured solution as "Release" mode with "x64" and build solution. DLL file will be created at "addons\MyTransformation\MyTransformation.dll"



# Register library at Qlik Replicate

Step 1: Go to path that Qlik Replicate was installed.

Step 2: Go to folder "addons".

Step 3: Copy folder "MyTransformation" from source code in above step which contain dll file and placed to folder "addons" in server.

Step 4: edit json file "addons_def.json" which it used for registration addons dll.
- Edit "lib_path" to "MyTransformation\\MyTransformation.dll" that it will link to dll file in step 3.
- Another configs set as default.

![5](https://user-images.githubusercontent.com/54891949/128848949-6698cca2-5249-4923-8af2-997059f6b677.jpg)

Step 5: Copy folder "lib" and "include" from source code and placed in folder "addons"

Step 6: Stop and Start Qlik Replicate service

Step 7: Qlik will register addons and you can see registered log at folder "data\log"


------

