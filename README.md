# RunPE vb.net

RunPE俗称借尸还魂，将一个PE注入到目标进程运行。原理是运行一个目标程序后挂起，在目标进程申请一块空间，在内存中将要运行的PE的各个参数写入到运行的目标进行中，包括头文件，区段等，并修改入口达到运行目的。    
主要是为了保护要运行的exe,你甚至可以将要保护的exe任意切分、加密，只要能在内存中将exe拼接成完整的PE就可以。省去在硬盘中产生镜像的过程。  
RunPE被广泛的用于加壳工具和病毒软件，比如著名的打包软件BoxedApp的插件就是创建了一个TCPSVCS.EXE的僵尸进程，将打包进去的exe通过注入该进程在内存中运行而达到打包的目的。  
貌似没见过vb.net版本，倒是有C#版本，但是又不少瑕疵，完善下改成vb.net的。 
