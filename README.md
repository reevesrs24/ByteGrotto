# ByteGrotto
Static AV-Evasion Via Code Cave Creation in Malware Portable Executables
<br/>
<br/>

>Comprehension follows perception.\
>\- *Phillip k. Dick* 


This repo is my rendition of the code cave creation static av-evasion technique first proposed by the paper [Optimization of code caves in malware binaries to evade machine learning detectors](https://www.sciencedirect.com/science/article/pii/S0167404822000426).


## Overview
Code cave creation within a Windows Portable Executable (PE) is an interesting technique to bypass malware classifiers which utilize the entire byte sequence or raw bytes of a PE as their input feature.  Code caves are the "slack space" or byte space within a PE section that is unused by the program, but is created in order to adhere to the `SectionAlignment` header within the PE.  All PE sections must adhere to the byte alignment specified by this header value and if the section data does not directly align itself on this boundary the compiler will add null bytes as padding to ensure that the section is the specified size.

<br/>

Code caves can be created by modifying the `RawAddress` variable within the each section's header.  Arbitrary data can then be added in between each section which can then be used to "confuse" malware classifiers which attempt to use an entire binary's raw data as an input feature.  

<br/>
<p align="center">
  <img width="460" height="300" src="images/code_cave.png">
  <p align="center"><i>Representation of the memory mapping of the original sample and a modified version with unused spaces introduced by the attacker (Yuste et al., 2022)</i></p>
</p>

## How it Works
The ByteGrotto application will take any x32 or .NET PE and and create code caves with data randomly chosen form a set of data sections harvested from the SysWOW64 Windows directory. The reasoning behind this is that these sections will presumably contain data that is seemingly benign to machine learning classifiers.  The PE transformation is done strictly in memory and upon each code cave iteration the program will evaluate the changes and determine if the changes have either increased or decreased the prediction score of the classifier.  If the score has increased then the program revert the changes and try again and if the prediction score has decreased it will keep the modifications.  This cycle will continue unitl the threshold value has been reached.  

<br/>
<p align="center">
  <img width="560" height="450" src="images/flowchart.png">
  <p align="center"><i>Flowchart for ByteGrotto's code cave method </i></p>
</p>
