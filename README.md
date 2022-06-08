# ByteGrotto
Static AV-Evasion Via Code Cave Creation in Malware Portable Executables
<br/>
<br/>

>Comprehension follows perception.\
>\- *Phillip k. Dick* 

<br/>

This repo is my rendition of the code cave creation static av-evasion technique first proposed by the paper [Optimization of code caves in malware binaries to evade machine
learning detector](https://www.sciencedirect.com/science/article/pii/S0167404822000426).

<br/>
## Overview

Code cave creation within a Windows Portable Executable (PE) is an interesting technique to bypass malware classifiers which utilize the entire byte sequence or raw bytes of a PE as their input feature.  Code caves are the "slack space" or byte space within a PE section that is unused by the program, but is created in order to adhere to the `SectionAlignment` header within the PE.  All PE sections must adhere to the byte alignment specified by this header value and if the section data does not directly align itself on this boundary the compiler will add null bytes as padding to ensure that the section is the specified size.

<br/>
Code caves can be created by modifying the `RawAddress` variable within the each section's header.  Arbitrary data can then be added in between each section which can then be used to "confuse" malware classifiers which attempt to use an entire binary's raw data as an input feature.  

<br/>
<p align="center">
  <img width="460" height="300" src="code_cave.png">
  <p align="center"><i>Fig. 2. Representation of the memory mapping of the original sample and a modified version with unused spaces introduced by the attacker (Yuste et al., 2022)</i></p>
</p>



