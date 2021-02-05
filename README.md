<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
***
***
***
*** To avoid retyping too much info. Do a search and replace for the following:
*** captonsnake, yaravent, twitter_handle, mccracken.landon@gmail.com, Yaravent, A tool to scan windows event logs with yara rules
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <h3 align="center">Yaravent</h3>

  <p align="center">
    A tool to scan windows event logs with yara rules
    <br />
    <a href="https://github.com/captonsnake/yaravent"><strong>Explore the docs »</strong></a>
    <br />
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#optimization">Optimization</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project
This tool will allow you to run a directory full of yara scans (must be stored in plain text files with the file extension .yara or .yar) against windows event logs (must be saved as .evtx). When running this program, it will initially load the yara rules. You may use the output to stderr to determine what logs are not loading correctly. Then it will run the scans against the logs in the logs directory. It may take a while. See the ways to optimize below on ways to improve. The output will be saved in the results directory in XML format. The XML format can be injest into a SIEM, or beautified for readability using an XML beautifier. 

To Do:
1. Different Ouptut options
2. Increase performace
3. Combined hits and misses file option
4. XML parser/beautify
5. Logging
6. Tests


### Built With

* [Evtx](https://github.com/williballenthin/python-evtx)
* [dicttoxml](https://pypi.org/project/dicttoxml/)
* [yara](https://pypi.org/project/yara-python/)



<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.


### Installation

1. Clone the repo
   ```sh
   # IMPORTANT: install yara following the instructions found on their website for your system
   python3 -m pip install yara-python
   python3 -m pip install dicttoxml
   python3 -m pip install python-evtx
   git clone https://github.com/captonsnake/yaravent.git
   ```




<!-- USAGE EXAMPLES -->
## Usage

1. get the help
```sh
python3 ./yaravent -h
```

2. Example command to start
```sh
python3 yaravent.py -y ./yara -l ./logs/ -r ./results/ -R -f
```

3. IF YARA IMPORT FAILS

When installing yara, the libyara library file will not always be stored in the the location that the pip installed yara looks in. To fix:
```sh
find / . -name libyara
cd [location that libyara is supposed to be]
ln -s [location of libyara] libyara
```

4. **CAUTION** There is a bug that can cause you to crash your host system

Because yaravent creates a process for each log in the log repository, there is the possibility that yaravent will create too many processes if you have too many logs. To fix simply set a maxlog and run it multiple times in the same directory. It will not run on logs that already have a results file. I have tested running against 8-10 logs at once.


## Optimization
Ways to optimize

1. Increase number of log files (break big logs up into smaller ones)
2. Reduce the number of yara rules
3. If you are running out of memory set a maxlog count using the CLI.


<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/captonsnake/yaravent/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- CONTACT -->
## Contact
Samual McCracken

Project Link: [https://github.com/captonsnake/yaravent](https://github.com/captonsnake/yaravent)
