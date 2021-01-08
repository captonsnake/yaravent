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
  <a href="https://github.com/captonsnake/yaravent">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Yaravent</h3>

  <p align="center">
    A tool to scan windows event logs with yara rules
    <br />
    <a href="https://github.com/captonsnake/yaravent"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/captonsnake/yaravent">View Demo</a>
    ·
    <a href="https://github.com/captonsnake/yaravent/issues">Report Bug</a>
    ·
    <a href="https://github.com/captonsnake/yaravent/issues">Request Feature</a>
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
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project
**To avoid retyping too much info. Do a search and replace with your text editor for the following:**
`captonsnake`, `yaravent`, `twitter_handle`, `mccracken.landon@gmail.com`, `Yaravent`, `A tool to scan windows event logs with yara rules`


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
   # install yara following the instructions found on their website
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


## Optimization
Ways to optimize
1. Reduce number of yara rules
2. Increase number of log files (break big logs up into smaller ones)
3. If you are running out of memory set a maxlog using the CLI


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
