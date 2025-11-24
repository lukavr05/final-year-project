// The main report template function.
// It sets up the document's structure, styling, and front matter.
#let report(
  title: none,
  author: none,
  group_name: none,
  course_name: none,
  unit_type: none,
  report_type: none,
  supervisor: none,
  date: none,
  location: "Egham",
  references: "references.yml", // Note: This file needs to exist.
  body 
) = {
  // === DOCUMENT SETUP ===
  set document(title: [#title], author: author)
  set text(font:"Nimbus Sans")
  set par(justify: true)
  set list(indent: 0.6cm)
  show link: underline
  show raw: set text(font: "CaskaydiaCove NF", weight: "regular")
  show raw.where(block: true): set block(inset: 2.5em)


  // === HEADING STYLES ===
  show heading: set block(above: 30pt, below: 30pt)

  // Chapter-level headings
  show heading.where(level: 1): set text(size: 20pt)
  show heading.where(level: 1): set heading(supplement: [Chapter])
  show heading.where(level: 1): it => block({
    let prefix = if it.numbering != none {
      it.supplement + [ ] + counter(heading).display(it.numbering) + [: ]
    }
    text(weight: "regular", prefix) + it.body
  })

  // Section-level headings
  show heading.where(level: 2): set text(size: 16pt)
  
  // === PAGE SETUP ===PROJECT
  // Add a header to all pages except the first one.
  set page(header: context {if counter(page).get().first() > 1 [#report_type #h(1fr) #author]})


  // === FRONT PAGE ===
  set align(center)
  
  text(22pt, "Final Year Project Report")
  v(3mm)
  line(length: 100%)
  text(30pt, weight: "bold", title)
  v(1mm)
  text(18pt, author)
  v(3mm)
  line(length: 100%)
  v(10mm)
  text(14pt, report_type + " submitted in part fulfilment of the degree of ")
  v(1mm)
  text(16pt, weight: "bold")[#course_name]
  v(10mm)
  text(18pt, "Supervisor: ", weight: "bold")
  text(18pt, supervisor)

  v(1fr) // Pushes the following content to the bottom of the page.

  block(height: 25%, image("media/rhul.jpg", height: 75%))
  text(14pt)[Department of Information Security#linebreak()Royal Holloway, University of London]
  v(15mm)
  
  text(12pt)[#date]

  pagebreak()

  // === TABLE OF CONTENTS ===
  set align(left)
  set heading(numbering: "1.1")
  
  outline(indent: 2em, title: "Contents")

  pagebreak()

  // === MAIN BODY ===
  // Reset page numbering for the main content.
  set page(numbering: "1", number-align: center)
  counter(page).update(1)

  // The main content of the document is passed in here.
  body

  // === BIBLIOGRAPHY ===
  // The bibliography has been commented out to prevent rendering errors.
  // To use it, create a "references.yml" file and uncomment the line below.
  // bibliography(references, title: "Bibliography")
}

// === DOCUMENT CONFIGURATION ===
// Apply the 'report' template to the entire document with the specified parameters.
#show: report.with(
  title: "Author Attribution of Binaries with Machine Learning",
  author: "Luka van Rooyen",
  course_name: "BSc Computer Science (Information Security)",
  supervisor: "Dr. Rachel Player",
  date: "October 2025",
  references: "references.yml" // Specify bibliography file here
)



// === MAIN CONTENT STARTS HERE ===

= Project Overview

== Introduction

The problem of attributing a piece of code, particularly a binary file, to a known author using machine learning is complex and must be decomposed into several logical steps @rosenblum2011. Moreover, the issue has applications in both malware forensics @alrabee2014 and threat detection, as it allows us to automatically identify and categorise malicious code authors @kalgutkar2019. This project explores predicting authorship by extracting and analysing features from compiled code and training machine learning models to interpret these features, assessing whether extracted features correspond to known malicious code or authors. The early objectives include: reviewing existing techniques for binary feature extraction, building a dataset of binaries from multiple authors, implementing and testing preliminary machine learning classifiers on extracted features, and evaluating early test results and refining the approach accordingly. The ultimate goal of the project is to evaluate whether distinctive patterns and features in compiled binaries can be analysed for reliable authorship attribution via machine learning methods. In doing so, we can potentially apply this attribution to determine whether the features of the binary are indicative of malicious code or known malicious authors.

== Aims and Objectives

Though the ultimate goal of the project is to predict authorship of binary files, this can be decomposed into two distinct sections: a *Binary Feature Extraction* component (see *Chapter 3*), and a *Machine Learning* component (see *Chapter 4*). Each section contributes equally to the final outcome of the project, but each has its own distinct set of goals. First, for the feature extraction component, we require:

#list(
    [A tool to statically extract _meaningful_ features from a binary file in either ELF or `.bin` format. The features should be determined according to their feasibility and compatibility with machine learning algorithms],
    [A tool to normalise these features in a way that can be easily interpreted for machine learning],
    [A report outlining the underlying theory and motivations of binary feature extraction, evaluating the methods and challenges]
)

And for the machine learning aspect, we require:

#list(
    [A tool to extract and format a dataset from publicly available datasets. The tool should use the binary feature extraction tool to get features and include the author as the label],
    [A machine learning model that, given a dataset and a list of features, can accurately predict authorship using regression models],
    [A report describing the theory that underpins the machine learning methods implemented, evaluating different models and comparing their performance],
)

#pagebreak()

/*
== Timeline

Before I begin coding, I plan to research the theory behind author attribution in the context of programming. This research will be collated into a brief report on *Author Attribution*, to define the different techniques on identifying a code author given their code, that will be included in the main project report. In essence, the practical side of the project will initially focus on the binary analysis and feature extraction aspect. I intend to research and produce prototypes of tool(s) that will be able to extract meaningful data from binary files that can be used by a machine learning algorithm. Following this, I will produce a *Binary Analysis and Feature Extraction Report*, documenting both my research and implementation process, as well as the key concepts and techniques applied.
#linebreak()
#linebreak()
For the machine learning aspect, I will first consolidate all applicable learning from my Machine Learning module (CS3920), alongside external research, and draft a plan regarding the application of this learning to the project. Subsequently, I will perform preliminary machine learning experiments, assessing and evaluating the results and documenting these in a *Machine Learning Report*.
#linebreak()
#linebreak()
Both the *Binary Analysis and Feature Extraction* and *Machine Learning* reports will be included in my interim report.
#v(1fr)
#align(end, "See next page for the in-depth first term timeline.")
#pagebreak()
*Weeks 1-2* (_September 29#super[th] - October 10#super[th]_)
#line(length: 100%, stroke: 0.5pt) 
- Review recommended literature, particularly pertaining to binary feature abstraction, as this will enforce early prototypes of feature extraction tools
- Explore supplementary readings using Google scholar to find academic literature on binary feature extraction and control graphs @theiling2000
*Deliverables:*
- Preliminary Project Plan
- Initial coding repository ready for coding experiments
#linebreak()
*Weeks 3-5* (_October 13#super[th] - October 24#super[th]_)
#line(length: 100%, stroke: 0.5pt)
- Complete research into author attribution in order to write the report
- Begin drafting report on binary feature extraction
- Set up coding environments (_i.e.-_ importing and installing necessary libraries/tools) based on research
- Begin prototyping different methods of binary feature extraction
  - Implement small test scripts on individual compiled binaries
*Deliverables:*
- Almost complete author attribution report
- Minimal scripts/algorithms for extracting features from binary files
- Rough draft of binary feature extraction report
#linebreak()
*Weeks 6-8* (_October 27#super[th] - November 7#super[th]_)
#line(length: 100%, stroke: 0.5pt)
- Refine development of binary feature extraction tool
- Continue binary feature extraction report
- Familiarise myself with machine learning techniques in Python (particularly using the `scikit-learn` library @pedregosa2011) and build a plan for my machine learning algorithm
*Deliverables:*
- A successful binary feature extraction tool
- A completed binary feature extraction report
- A plan for the machine learning aspect of the project
#linebreak()
*Weeks 9-11* (_November 10#super[th] - November 21#super[st]_)
#line(length: 100%, stroke: 0.5pt)
- Locate open source datasets that can be used in training (such as from the Google Code Jam @caliskan2015)
- Begin producing prototype machine learning algorithms, built to specifically analyse the features extracted by my completed extraction tool
- Assess results of preliminary machine learning experiments, in order to refine the algorithm
- Document key insights to include in my interim report and gauge what additional work needs to be done
#pagebreak()
*Deliverables:*
- Preliminary machine learning algorithms/experiments
- Evaluation of model performance and challenges
#linebreak()
*Weeks 12-14:* (_November 24#super[th] - December 5#super[th]_)
#line(length: 100%, stroke: 0.5pt)
- Refine model further using evaluation from previous week
- Begin training and using external datasets to determine efficacy on untrained datasets
- Develop interim report further, including binary feature extraction and evaluations from previous weeks 
*Deliverables:*
- A more refined machine learning algorithm that can measurably produce more accurate results
- An updated interim report that reflects this development
#linebreak()
*Week 15* (_final week_)
#line(length: 100%, stroke: 0.5pt)
- Conduct any further necessary code revisions, whether it be for the binary extraction tool or the machine learning algorithm
- Finalise interim report
#pagebreak()
== Risk Assessment & Mitigations

#table(
  columns: (15%, 25%, 10%,10%, 10%, 30%),
  inset: 10pt,
  table.header(
    [*Risk Category*], [*Risk Description*], [*Likelihood (1-5)*],[*Impact (1-5)*], [*Risk- Level (1-25)*], [*Mitigation Strategies*]
  ),
  [*Technology*], [Hardware failure/Data loss], [2], [4], [8], [Use Version Control Systems, such as Gitlab, to ensure any files are backed up externally, as well as committing regularly. Constantly save work after editing locally.],
  [],[Computational resource limitations], [3], [3], [9], [Design code with efficiency in mind, making sure to not unnecessarily drain resources. Use my main PC with better hardware rather than laptop when performing large tasks.],
  [*Security*], [Including malicious binaries in datasets], [2], [5], [10], [Include only non-malicious binaries in dataset initially as proof of concept, then move to malicious binaries with very *limited* access to any external programs. Consult with supervisor on how to handle these malicious binaries.],
  [*Technical*], [Scarcity of viable Datasets], [4], [4], [16], [There are not many varied datasets that are easy to acquire, so I will have to manually search for some external binary files with their authors and build on top of minimal datasets.],
  [*Personal*], [Machine Learning and Binary Feature Extraction Overhead], [5], [3], [15], [Due to my limited experience with Machine Learning _and_ Binary Feature Extraction, I will have to allocate time to learn these technologies in themselves, as well as best practices/optimisations that can be done.],
  [], [Poor planning/task estimation], [3], [5], [15], [Due to my inexperience, I will need to carefully consider how I break down the project into sections. I will consistently meet with my supervisor in order to evaluate my task estimation.],
  [],[Imbalance between coding and report-writing],[3],[3],[9],[Continually update my report alongside coding, so that there is not a deficit between the two components.]  
)
#pagebreak()
*/
= Author Attribution

== Introduction To Author Attribution

In this section, we will explore the theories and practices pertaining to the attribution of a piece of code to a known author. While not all these methods are easily measurable in the context of machine learning, the underpinning concepts will heavily influence the approach to author attribution. Abstractly, the process involves identifying an author's "fingerprint", and using syntactic identifiers within their writing style in order to determine whether a piece of code fits their respective fingerprint. In the context of computer security, accurately and reliably identifying adversaries is a very desirable goal @stein2009. This capability not only supports forensic investigations and accountability but may also serve as a deterrent to future attacks by reducing the perceived anonymity of adversaries. In this report, we will delve into some objectives that author attribution aims to achieve, some metrics that can be used for identifying authors, then putting these metrics in context and evaluating their relevance to this project's goals and technical implementation.

== Objectives of Author Attribution

The following objectives are derived from V. Kalgutkar et al.'s article "Code Authorship Attribution: Methods and Challenges" @kalgutkar2019, and I believe they concisely represent the core goals of authorship attribution. Their descriptions have been paraphrased for clarity.

#list([_*Authorship Identification*_ -- Finding the most likely author of a specific work from a set of given candidate authors.],[_*Authorship Clustering*_ -- Grouping works based on stylistic similarities to identify groups in which an author has collaborated.],
[_*Authorship Evolution*_ -- Analysing changes in an author's code style; the way their programming skills, preferences, and writing style evolve over a period of time.],
[_*Authorship Verification*_ -- Determining the author of a given piece of code, to ensure that innocent code has not been tampered with by malicious authors.], indent: 0.6cm, spacing: 0.4cm, marker: [--])
#linebreak()
Following these objectives, we can determine which ones are most relevant to this project. The two main goals I intend to satisfy within this project will be author identification and authorship clustering. Not only do these perfectly encapsulate the goals of the project, they are also the most feasible in the application of machine learning. Authorship verification does not hold as much relevance to the project, and authorship evolution will be difficult to measure using machine learning techniques due to its dynamic nature. 
#pagebreak()

== Code Author Analysis Metrics

Now that the goals and motivations have been established, we focus now on the precise metrics through which we can measure coding style. Before considering machine learning, however, it is important to understand which measurable elements of code can make an author identifiable. These can broadly be categorised into lexical, syntactic, semantic, and structural metrics @rosenblum2011 @kalgutkar2019.

#list([*Lexical Metrics* -- These describe surface-level textual properties such as: variable naming conventions, identifier lengths, use of white-space, comment density, or preferred keywords.],

[*Syntactic Metrics* -- These measure the arrangement of language constructs. For example, the frequency of control structures such as loops (e.g., `for`, `while`) or conditionals (e.g., `if`, `else`), average nesting depth, or use of specific programming conventions.],

[*Semantic Metrics* -- These capture the author’s problem-solving habits @stein2009: API usage, data-flow choices and preferred algorithms.],

[*Structural and Behavioural Metrics* -- These focus on how a program behaves and its higher-level organisation. ],
indent: 0.6cm, spacing: 0.4cm,
)
#linebreak()

Collectively, these metrics form the conceptual foundation for feature extraction. They embody the "fingerprints" that machine learning models aim to quantify given a set of data. The method for extracting these features and how they manifest in compiled binaries will be discussed further in *Chapter 3*.

== Applicable Metrics in the Context of Machine Learning

When considering which metrics to focus on in the context of machine learning, it is necessary to identify which of the previously defined metrics can be represented as measurable and quantifiable features that can be mathematically represented. While lexical and syntactic traits are the most intuitive to analyse, their availability depends on the format of the code being studied. In the context of compiled binaries, the focus of this project, many high-level stylistic markers — such as variable naming or spacing — are removed during compilation @caliskan2015. Binaries are also often obfuscated (more in *Chapter 3*), especially by malicious authors @claudia2023, adding another layer of complexity. Therefore, the focus must shift toward metrics that either survive compilation or can be inferred through disassembly via decompilers.

First, we can examine features that fall under the *lexical* category:
#list(
  [*Line Length/Count* -- The length of lines and their total number in the file.],
  [*Number of Operands/Variables* -- The count of operands and variables in the file.],
  [*Instruction Frequency* -- Statistical counts of machine instructions (e.g., `mov`, `cmp`, `jmp`), which can also indirectly reflect an author’s structural and syntactic tendencies.],
  [*Instruction n-grams* -- Short sequences of instructions that act as stylistic proxies for common control or data manipulation patterns.],
  indent: 0.6cm, spacing: 0.4cm,
)
#pagebreak()
Next, the main *syntactic* features:
#list(
  [*Average Function Size/Count* -- The distribution of function lengths and total function count, potentially indicating individual decomposition or abstraction styles.],
  indent: 0.6cm, spacing: 0.4cm,
)
The *semantic* features include:
#list(
  [*Control-Flow Graph Features* -- Quantitative properties such as loop depth, branching frequency, and cyclomatic complexity @theiling2000 that reveal higher-level structural habits.],
  [*Dataflow Analysis* -- The way data moves throughout the program's runtime.],
  indent: 0.6cm, spacing: 0.4cm,
)

The main *behavioural* feature that we will use is:
#list(
  [*Library and API Call Usage* -- Preferences in system or library calls that persist across compilations.],
  indent: 0.6cm, spacing: 0.4cm,
)

Among all these features, it should be taken into consideration that what may appear to be features inside extracted binaries may also simply be artifacts produced by compilation @ali2025. This will mean taking extra care in the analysis of features extracted, ensuring that artifacts can be identified and removed from consideration.
#linebreak()

== Summary and Conclusion

Over the course of this chapter, we have examined the theoretical and practical foundations of code authorship attribution, outlining its key objectives, measurable stylistic metrics and evaluating their applicability within a machine learning context. While lexical and syntactic features offer rich descriptive potential in source-code-level analysis, their usefulness significantly diminishes in compiled binaries due to the loss of high-level stylistic elements (variable names, whitespace/commenting style) during compilation and obfuscation.

Consequently, this project focuses on features that are retained during the compilation process and remain quantifiable in binary form. Metrics such as control-flow complexity and library call usage provide the strongest candidates for representing authorial style in compiled executables. These features, though abstracted from the original source, can still capture meaningful patterns of authorial behaviour suitable for machine learning classification and clustering tasks.

However, it is also evident that binary authorship attribution faces notable challenges, namely compilation artifacts, obfuscation and time complexity.

The following chapter will build upon these conceptual foundations by investigating how the identified metrics can be systematically derived from compiled binaries. It will focus on the practical processes of extracting, structuring, and preparing these features for use in machine learning models.

#pagebreak()

= Binary Feature Extraction

== Introduction to Binary Feature Extraction

In this chapter, we examine the process of taking compiled binary files as input and extracting meaningful features from it. Building upon the attribution metrics discussed in *Chapter 2*, we can tailor the extraction process to yield only the features we care to examine, ignoring some more complex analysis. This process is non-trivial; compilers remove or alter high-level information such as variable names, indentation, or comments, leaving behind machine instructions and structural artefacts @alrabaee2020. As a result, feature extraction must operate at a lower abstraction level. 

Furthermore, we will establish the concept of feature extraction: the types of analysis (static and dynamic), as well as their challenges. On top of this, developing a feature extraction pipeline will be very important, which will also be developed further in this report.

== Static and Dynamic Analysis

When considering analysis of binary files, there are two main ways methods: static analysis and dynamic analysis. Static analysis, on the one hand, examines the binary _without_ executing it. This limits the features we are able to extract, but nonetheless we can still access features such as control flow. Dynamic analysis, however, focuses on the changes made during a binary file's runtime. This allows us to observe system/API calls and execution traces as they occur. While this broadens the scope for potential features, in the context of this project, it will be unsafe as we aim to determine the authors of potentially malicious code. This means that malicious code would have to be run in order to perform dynamic analysis. Of course, this presents a serious security risk, which will be avoided by excluding dynamic analysis from this project.

== Feature Extraction Pipeline

The binary feature extraction pipeline represents the process through which compiled binaries are transformed into numerical features suitable for machine learning. The goal is to move from raw executable code (simply a sequence of bytes) to a structured set of features that captures meaningful stylistic or structural traits of the binary file. most of my pipeline will be using Python, as there are plenty of available and accessible libraries, as well as providing easier formatting when converting to machine learning (which will also be done in Python).

The basic structure of the pipeline is as follows:

#set align(center)
#linebreak()
*Binary Input* #sym.arrow.r.double *Disassembly* #sym.arrow.r.double *Feature Extraction* #sym.arrow.r.double *Feature Normalisation*
#set align(left)

=== Binary Input/Preprocessing
The pipeline begins with compiled executables that we want to extract from(e.g., `.exe` or `.bin` files). These binaries are read in raw byte form using Python’s in-built I/O mechanisms. The main aim of this stage is to validate that the file exists, detect the architecture (e.g., x86, x64, ARM) that it was compiled on/for and convert the file into a set of bytes. All these prepare the file for the next stage: disassembly.

=== Disassembly
At this point, the binary data is still *machine code* - unreadable to humans and difficult to analyse. The disassembly stage converts this machine code into assembly language, which represents each machine instruction symbolically (e.g., `mov`, `jmp`, `call`). Extracting these is very useful in determining control flow and instruction frequency in the faeture extraction phase.

=== Feature Extraction
Once the binary is disassembled, the next step is to extract measurable features that can capture the stylistic or structural characteristics of the author’s code, to be fed into a machine learning algorithm.

=== Feature Normalisation
Different binaries vary in size and instruction count, so raw frequency counts are normalised (by using the average frequency per instruction) to allow fair comparison between samples. 

== Practical Binary Analysis

=== Basic Extraction
Before we can extract meaningful data, we need to examine how we can even read a binary file in code. First, we will need a minimal file to test on. Below is a simple C program `example.c` that will be used for testing:

```c
int main() {
    int a = 0;
    int b = 5;
    int c = a + b;
}
```

Compiling this using the `gcc` compiler on a Linux system gives `example1`, an ELF 64-bit LSB pie executable, which we can pass into a Python program for some basic analysis. Below is a minimal Python script for extracting raw binary data from a file:

```py
def extract(path):
    with open(path, "rb")as file:
        code = file.read()

    return code
```

Running this script produces the following output (which has been heavily truncated):

```
b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\
x01\x00\x00\x00@\x10\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00`6
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\r\x00@\x00\x1e\x00\x1d\x00\x06
\x00\x00\x00\x04\x00\x00\x00@\x00\x00\x00\x00\x00
\x00\x00@\x00\x00\x00\x00\x00\x00\x00@\x00\x00
\x00\x00\x00\x00\x00\xd8\x02\x00\x00\x00\x00\x00\x00\xd8\x02\x00\x00
\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x03
\x00\x00\x00\x04\x00\x00\x00\x18\x03\x00\x00\x00\x00\x00\x00\x18\x03\x00\x00
\x00\x00\x00\x00\x18\x03\x00\x00\x00\x00\x00\x00\x1c
\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00
\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
[...]
```
=== Using The `capstone` Framework
While extracting the raw binary data is useful, it is difficult to extract something meaningful just from these byte strings. To translate this low-level data into readable assembly instructions, we can use the `capstone` disassembly framework, a widely used, lightweight, and multi-architecture disassembler written in C with Python bindings @capstone2013.

```py
from capstone import *

def dissassemble(path):
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    with open(path, "rb") as file:
        code = file.read()

    for i in md.disasm(code, 0x1000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
```

We first initialise the Python object for `capstone` with class `Cs`. This class requires two arguments: the hardware architecture & the hardware mode. In this sample, we specify 64-bit code for X86 architecture.

After setting it up, we use the `disasm` function, taking the byte string we get from the code, as well as the address for the first (relative) instruction `0x1000`. Then, for each instruction read in, we print the relative address, mnemonic and the op string.

Dissassembling `example1` gives us the following (truncated) output:
```
0x1000:	jg	0x1047
0x1002:	add	r8b, byte ptr [rcx]
0x1006:	add	dword ptr [rax], eax
0x1008:	add	byte ptr [rax], al
0x100a:	add	byte ptr [rax], al
0x100c:	add	byte ptr [rax], al
0x100e:	add	byte ptr [rax], al
0x1010:	add	eax, dword ptr [rax]
0x1012:	add	byte ptr ds:[rcx], al
0x1015:	add	byte ptr [rax], al
0x1017:	add	byte ptr [rax + 0x10], al
0x101a:	add	byte ptr [rax], al
[...]
```

Instantly, a major issue becomes apparent, being that the number of instructions is far greater than what we would expect for such a simple program. This occurs as, when compiled using `gcc` with default options, the generated ELF file includes not only user-defined functions but also large amounts of startup and library code introduced by the C runtime and standard library. Consequently, disassembling the entire binary yields a far greater instruction count than the source code suggests.

There are myriad approaches to extract information from just the `main` function. Namely, instead of compiling using the command `gcc example1.c -o example1` (producing an ELF file), we can create an object file using `gcc -c example1.c -o example1.o`. However, due to this project using external datasets of binaries using any number of compilers, we will need to produce an extraction tool that can dynamically remove "noise" produced by compilers and runtime environments. 

=== Analysing Binary Structure

To tackle this newly arisen issue of compiler artefacts produced in the compilation process, we will need to analyse how binary files are structured so we can extract only the user-generated sections. ELF files, which are one of the simplest formats of binary structure, are split into several sections @tiscommittee1995:

#set align(center)
#table([*ELF Header*],[*Program Header Table*], [`.text`], [`.rodata`], [`.data`], [...], [`.init`], [`.fini`], [...], [*Section Headers Table*])
#set align(left)
#linebreak()
#list(
  [*ELF Header* -- Contains the file type, architecture and entry point],
  [*Program Header Table* -- Describes how to load the program into memory],
  [*`.text`* -- The main executable code],
  [*`.rodata`* -- Read-only data, such as constants],
  [*`.data`* -- Global/static variables that are initialised in the program],
  [*`.init`* -- The initialisation code that runs _before_ the `main` function],
  [*`.fini`* -- The finalisation code that runs _after_ the `main` function],
  indent: 0.6cm, spacing: 0.4cm,
)
_Note that this is not a comprehensive structural breakdown, but contains all sections relevant to the project._ 

From this table, we can see that the `.text` section is what we are looking to extract. Windows also produces PE files, which also include a `.text` section, even though most other sections are named different to that of ELF's. There are several Python libraries available for breaking down ELF and PE files into their sections. For this project, we will be using the `lief` library, as it can handle ELF (Linux), PE (Windows) and has an easy-to-use API.

```py
import lief

def getText(path):
    binary = lief.parse(path)

    text_section = binary.get_section(".text")

    print(f".text section offset: {text_section.file_offset:#x}")
    print(f".text section size:   {text_section.size:#x}")
    print(f".text virtual addr:   {text_section.virtual_address:#x}")

```

Here, we use the `lief` library to get some information about the `.text` section of the ELF file. Namely, we can extract the offset, size, and virtual address of the section. Running this code on the binary `example1` yields the following output:

```
.text section offset: 0x1040
.text section size:   0x10d
.text virtual addr:   0x1040
```

== Instruction Frequency

Now, given that we can extract the `.text` section of a binary file, we can look at extracting features from given this information. First, we focus on *Instruction Frequency*. 

=== Extracting Raw Instruction Counts

We can use the following function in conjunction with our extraction code to determine the count of each instruction, and hence the instruction frequency. We can store the counts of each mnemonic using a Python dictionary object.

```py
def getInstructionCounts(text_bytes):
   [...]
    for i in md.disasm(text_bytes, 0x1000):
        mnemonic = i.mnemonic
        if mnemonic in instruction_counts:
            instruction_counts[mnemonic] += 1
        else:
            instruction_counts[mnemonic] = 1

    for instr, count in instruction_counts.items():
        print(f"{instr}: {count}")
```

Providing the output:
```
xor: 3
mov: 15
pop: 3
and: 1
push: 4
lea: 5
call: 3
hlt: 1
nop: 8
cmp: 3
je: 5
[...]
```

This output is far more reasonable in terms of instruction counts for such a simple program. While some may artifacts may be preserved, we can now see accurate counts for many main assembly instructions.

=== Normalising Instruction Counts

The next logical step is to normalise the instruction counts, as some longer binaries may have higher counts of instructions overall, we care about the relative *frequencies* (or ratios) of these instructions. As well as this, some binary files may contain a wider array of instructions, which could skew data if we dynamically inspect the instruction counts. This requires special attention, and for the purposes of the project we will focus on the main instructions that are most common and will lead to more accurate authorship attribution. 

Through the research of Caliskan-Islam et al. @caliskan2015 and Rosenblum et al. @rosenblum2011, they determined instructions that pertain to control flow (`jmp`, `call`, `ret`, `cmp`), memory control (`mov`, `push`, `pop`) and arithmetic (`add`, `sub`) can be used to indicate authorship. The ratios of these will be considered and added as part of the *feature set* of the machine learning aspect.

In order to determine the frequencies of instructions, we will first get the total number of instructions in the `.text` section by iterating through the dictionary object returned by `getInstructionCounts`. Then, by defining some relevant instructions, we can get their count from the dictionary and trivially calculate their frequency by dividing the count by the total number of instructions. If the instruction is not found in the dictionary, we will simply set the frequency to 0. 

```py
def getInstructionFrequencies(counts):

    relevant_instructions = ["jmp", "call", "ret", "cmp", "mov", "push", "pop", "add", "sub"]
    freqs = np.zeros(len(relevant_instructions), dtype=float)
    total_instructions = 0

    for count in counts.values():
        total_instructions += count

    for i in range(0, len(relevant_instructions)):
        current_instr = relevant_instructions[i]
        if current_instr in counts:
            c = counts.get(current_instr)
            freqs[i] = c / total_instructions
        else:
            freqs[i] = 0

    print(freqs)
```

Performing this on `example1` produces the output:

```
[0.03703704 0.0617284  0.0617284  0.03703704 0.25925926 0.04938272 0.02469136 0.02469136 0.02469136]
```

Which is a `numpy` array of type `float`, containing the frequencies neatly formatted, as `numpy` and `sklearn` are extremely compatible. 

If we run the program on the ELF files `example1`, `example2` and `example3` (found in the `product/binary-feature-extraction/examples` directory), we can visualise the distribution of the relevant instructions.

#figure(
  image("media/bfe_inst_frq.png", width: 74%)
)

From the graph, we can deduce that the `mov` instruction is the most common throughout the examples, with the others having tiny but identifiable differences.

To summarise our findings so far with instruction counts: analysing instruction frequency provides a practical and effective method for extracting stylistic features from compiled binaries. Although raw instruction counts vary significantly between programs due to differences in size, optimisation level, and compiler behaviour, focusing on the most common and semantically meaningful/relevant instructions enables the extraction of features that are more reliable. By isolating the `.text` section using Lief and disassembling it with Capstone, the tool captures a consistent representation of program behaviour while avoiding unrelated data or metadata. This reduces compiler-generated noise and emphasises patterns that are more indicative of programmer style rather than compilation artefacts.

== N-grams

N-grams are a very valuable tool for authorship attribution and have been used widely in research @kalgutkar2019 as they are robust and survive compilation @burrows2007. Put simply, instruction n-grams are a sequence of $n$ consecutive instructions, represented by their mnemonics (e.g., `mov`, `jmp`). There are several types of n-grams: 
#list(
[With $n = 1$, we have *unigrams*, where we take a 1-dimensional sequence of instructions, in essence the sequence of instructions (e.g., `[mov, jmp, cmp, cmp, add]`).],
[With $n = 2$, we have *bigrams*, where we take a 2-dimensional sequence of instructions. (e.g., `[[mov, jmp], [jmp,cmp], [cmp, cmp], [cmp, add]]`)],
[With $n = 3$, we have *trigrams*, where we take a 3-dimensional sequence of instructions. (e.g., `[[mov, jmp, cmp], [jmp, cmp, cmp], [cmp, cmp, add]]`)],
indent: 0.6cm, spacing: 0.4cm,
)  

=== Extracting Instruction n-grams

To extract the n-grams of a sequence of instructions, we can use the following function, which takes as its parameters: the code section and the degree of $n$.

```py
def getNGrams(code: bytes, n):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = []

    for i in md.disasm(code, 0x1000):
        instructions.append(i.mnemonic)

    ngrams = []

    for i in range(len(instructions) - n + 1):
        ngram = tuple(instructions[i:i + n])
        ngrams.append(ngram)
    
    return ngrams
```
This function first extracts the raw list of instructions, then using a sliding window approach, extracts each n-gram as a tuple and stores them all in a list.

Executing this function on `example` with $n = 2$ gives us an output:

```
[('xor', 'mov'), ('mov', 'pop'), ('pop', 'mov'), ('mov', 'and'), ('and', 'push'), ('push', 'push'), ('push', 'xor'), ('xor', 'xor'), ('xor', 'lea'), 
[...]
```

And with $n = 3$:
```
[('xor', 'mov', 'pop'), ('mov', 'pop', 'mov'), ('pop', 'mov', 'and'), ('mov', 'and', 'push'), ('and', 'push', 'push'), ('push', 'push', 'xor'), ('push', 'xor', 'xor')
[...] 
```

=== Normalising Instruction n-grams

Now we have extracted the raw n-grams, the challenge of normalising this list of tuples in a way that can be processed by a machine learning algorithm. A well-known and proven method is TF-IDF (Term Frequency - Inverse Document Frequency). It is essentially a way to weight the importance of a word (or token) in a document, _relative_ to a collection of documents. This means that tokens which appear a lot in one document won't affect the overall score as much @bafna2016. In the context of the project, each "document" is a binary file and each "token" is an instruction n-gram. However, this normalisation is done at the dataset level, as the IDF analysis requires the entire corpus. This means, for now, we can just do the TF part, where we can store all the unique n-grams in a file, with their count. Then, when we have an entire dataset, we can implement a pipeline (more in *Chapter 4*) that can handle the IDF. 


== Control Flow

Analysing the control flow of a binary file can be a very good indicator of authorship @hayes2010. The use of *Control Flow Graphs* (CFGs) are imperative to ascertain how a program is structured. 

=== Extracting A Control Flow Graph

While it would be possible to create a CFG from scratch in Python, I believe it will be more time and memory efficient to use the `angr` library, which can create CFGs for any binary file easily. Using elementary objects, we can extract the CFG itself - and more importantly - the information contained within it. As shown below, the extraction itself is very simple:

```py
def getControlFlowGraph(path):
    binary = angr.Project(path, load_options={"auto_load_libs": False})

    cfg = binary.analyses.CFGFast()
    
    return cfg
```

We first instantiate a `Project` object, which in essence stores everything related to the binary we are analysing. The object takes the path to the binary file, as well as some load options as parameters. the `auto_load_libs` property simply specifies that we want the tool to *ignore* shared libraries. As the CFG analysis by default does not distinguish between code from different binary objects @shoshitaishvili2016.

Using the following code, we can extract some meaningful features from the extracted CFG:

```py
print("Graph Type:", cfg.model.graph)
print("\nNodes:")
for node in cfg.model.graph.nodes():
    print(f"Node address: {hex(node.addr)}\tNode size: {node.size}")

print("\nEdges:")
for src, dest, data in cfg.model.graph.edges():
    print(f"{hex(src.addr)} -> {hex(dest.addr)}")
```

Which provides us the output:

```
Graph Type: DiGraph with 36 nodes and 36 edges

Nodes:
Node address: 0x401040  Node size: 33
Node address: 0x401000  Node size: 16
Node address: 0x401070  Node size: 19
Node address: 0x4010a0  Node size: 36
Node address: 0x4010e0  Node size: 13
Node address: 0x401120  Node size: 9
Node address: 0x401129  Node size: 36
[...]

Edges:
0x401040 -> 0x500000 
0x401000 -> 0x401012
0x401000 -> 0x401010
0x401070 -> 0x401098
0x401070 -> 0x401083
0x4010a0 -> 0x4010d8
[...]
```

=== Extracting Features from the Control Flow Graph

Now we have our CFG available for analysis, we can begin to extract some features that will be useful for machine learning applications. The simplest features to be extracted are the number of nodes and edges, calculated by:
```py
g = cfg.model.graph

num_nodes = len(g.nodes())
num_edges = len(g.edges())
```

So far, this is quite trivial. An important feature of the `angr` modules is that they are compatible with `networkx`, a very useful model in graph analysis @hagberg2008. We can use some features of this module to get some more values out, such as the graph density (the ratio between the actual edges and the maximum number of edges possible) and cyclomatic complexity (a measure of the complexity of a graph). We can extract these using the following:



#pagebreak()


= Machine Learning

== Introduction to Machine Learning

Now we have a set of features extracted by our binary feature extraction tool, we can move onto creating a machine learning model that will be able to determine the authorship of a binary file based on this feature set. In machine learning, we deal with two main sets, $X$ being the feature set (a list of features), and $y$ being the label set (the set of authors). For each binary file in the dataset, we include the set of extracted features with the author label. Below is a visual representation of the what is included for each binary sample in the dataset:

#table(
  columns: 13,
  align: (_, y) => if y == 0 { center } else { left }, 
  table.cell(colspan: 9, [*Instruction Frequencies*]),
  table.cell(colspan: 4, [*CFG Features*]),
  [`jmp`], [`call`], [`ret`], [`cmp`], [`mov`], [`push`], [`pop`], [`add`], [`sub`], [`num_edges`], [`num_nodes`], [`density`], [`complexity`]
)

== Assembling a Dataset

All the features we have implemented thus far are useless without being able to apply them to a dataset. Many researchers use the Google Code Jam dataset, which includes several examples of code generated by the same author, with labels included. However, the main issue is that all solutions are stored as source code. As well as this, there are several different languages used in the set of solutions, so we will have to manually extract and compile only C and C++ files. 

The dataset itself comes in the form of a Comma Separated Variable (CSV) file (downloaded from https://www.kaggle.com/datasets/jur1cek/gcj-dataset, specifically `gcj2020.csv`), meaning fields are separated by commas. The file kindly provides us the structure of the dataset on the first line:

#set align(center)
```
file,flines,full_path,round,solution,task,username,year
```
#set align(left)

Most of these features are slightly ambiguous in terms of their naming, but the usable features are clear enough. These are:

#set align(center)
#table(
  columns: 3,
  align: left,
  table.header([*Column*], [*Description*], [*Example*]),
  [`file`], [The file index], [`0` (for the first file)],
  [`full_path`], [The name and type of the file], [`0000000000214847.CPP`],
  [`solution`], [The full source code of the file itself], [`cout << "Hello, world!"`],
  [`username`], [The username of the code author], [`author123`],
)
#set align(left)

The main task is now to extract the desired features to reconstruct the raw source code, (keeping the information about the author) and compiling it into a binary that can be analysed by the extraction tool. 

=== Parsing the CSV

First, we need to test how we can extract information from the CSV file. Thankfully, the Python library `csv` has some tools for easily extracting information from files in this format. Below is a simple function to extract the first entry of the CSV file:

```py
import csv

def parseCSV(path):
    with open(path, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        row = next(reader) # Only extracting the first row
        
        username = row['username']
        file_id = row['file']
        source_code = row['flines']
        file_name = row['full_path']

    print(f"Username: {username}\nFile ID: {file_id}\nFile Name: {file_name}\nSource Code: {source_code}")
```

Which correctly provides us with the output:

```
Username: xiaowuc1
File ID: 0000000000214847
File Name: 0000000000214847.CPP
Source Code: #include <algorithm>
#include <bitset>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <random>
#include <set>
#include <stack>
#include <vector>

using namespace std;

// BEGIN NO SAD
#define rep(i, a, b) for(int i = a; i < (b); ++i)
#define trav(a, x) for(auto& a : x)
#define all(x) x.begin(), x.end()
#define sz(x) (int)(x).size()
typedef vector<int> vi;
// END NO SAD
[...]
```

=== Extracting the Source Code

The dataset generation will first, in a `src/` directory, parse the source code. Each author will have a seperate directory which will be named after their username and contain all code they have completed. The following code uses the code above to create the src directory and dynamically create the username directory to store all the code.

```py
def parseCSV(path):

    # The output directory
    OUTPUT_DIR =  Path("test/src")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    [...]

    out_dir = OUTPUT_DIR / username
    out_dir.mkdir(parents=True, exist_ok=True)

    if file_name.lower().endswith(".cpp"):
        ext = ".cpp"
    else:
        ext = ".txt" # default

    new_file_name = file_id + ext
    src_path = out_dir / new_file_name

    with open(src_path, "w", encoding="utf-8") as f:
        f.write(source_code)

```

The function specifies an absolute output directory, `OUTPUT_DIR`, which is where all the newly generated directories will go. The flags `parents` and `exist_ok` ensure that we can create parent directories and avoid any issues if the directory already exists (such as the case when an author has multiple solutions). The code then checks the file extension so that it can create the correct file when adding it to the directory. When we run this code, we can see it correctly creates the new directories and the file, which contains the entire source code.
```
.
└── src
    └── xiaowuc1
        └── 0000000000214847.cpp
```

If we run the code on a larger subset (of size 20) of the dataset we get the following file structure:

```
  src
    ├── Benq
    │   ├── 0000000000210bf5.cpp
    │   ├── 0000000000210d90.cpp
    │   ├── 0000000000211175.cpp
    │   ├── 0000000000213183.cpp
    │   ├── 0000000000216261.cpp
    │   └── 0000000000216a0b.cpp
    ├── cki86201
    │   ├── 0000000000210a72.cpp
    │   ├── 0000000000210b57.cpp
    │   ├── 0000000000210efb.cpp
    │   ├── 0000000000212170.cpp
    │   ├── 0000000000213ed5.cpp
    │   ├── 0000000000214554.cpp
    │   └── 0000000000215114.cpp
    ├── Golovanov399
    │   ├── 0000000000217a48.cpp
    │   └── 0000000000217a6a.cpp
    └── xiaowuc1
        ├── 0000000000210be4.cpp
        ├── 0000000000210dfc.cpp
        ├── 0000000000211171.cpp
        ├── 000000000021301e.cpp
        └── 0000000000214847.cpp
```
Meaning we have successfully extracted the C++ files and placed them in directories for their respective authors.

=== Compiling the Source Code

The next step in generating our dataset of binary files is to take this source code and compile it into ELF format. Before we can implement this into our current generation script, we need to create a function that can automatically compile C++ source code into ELF binaries. So far in the project, we have based the compilation on pure C, using the `gcc` compiler. Because we are now dealing with C++, we have to use the C++-enabled version of the `gcc` compiler: `g++`. The `-O2` flag specifies compiler optimisations @gccdocs, with `-O2` speeding up compilation enough to feasibly compile all the binaries in the dataset in a reasonablre timeframe whilst preserving enough of the source binary information. We can use the `subprocess` library to enable us to run commands dynamically (after giving the file `rwx` permissions).

```py
def compileSourceCode(src_path, bin_path):
    try:
        cmd = ["g++", "-O2", "-o", str(bin_path), str(src_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)

        if result.returncode != 0:
            print(f"FAILED at {src_path} -> {result.stderr}\n")
            return False

        print(f"SUCCESS: {src_path}\n")
        return True

    except subprocess.TimeoutExpired:
        print(f"TIMEOUT: {src_path}\n")
        return False
```

By capturing the output of the subprocess, we can determine whether the file successfully compiled or not, and capture any relevant output (to return the error message). Additionally, we want to ensure that the program does not get stuck in an infinte loop, so we account for timeout errors as well. In the final tool, we can use these outputs and store them in `.log` files, to keep track of what is happening.

=== The Final Tool

Given all the components discussed above, we can now combine them all to create a single script that parses the entire CSV file, extracts the source code (organising by user), and compiles it to provide a set of binary files. Once we have all of our binary files, we can build a dataset.

First, we must set up the environment, importing all necessary modules, setting some important variables and defining the paths of the files to be used.

```py
import csv
import subprocess
from pathlib import Path
from tqdm import tqdm

CSV_PATH = "../gcj2020.csv"                  
OUTPUT_SRC_DIR = Path("dataset/src")
OUTPUT_BIN_DIR = Path("dataset/bin")
NUM_FILES = 75
COMPILER = "g++"
COMP_FLAGS = ["-O2"]

OUTPUT_SRC_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_BIN_DIR.mkdir(parents=True, exist_ok=True)

success_log = open("compile_success.log", "w")
fail_log = open("compile_fail.log", "w")
```

Now, we modify our `compileSourceCode` function to write to the log files rather than just printing to the command line. 

```py
def compileSourceCode(src_path: Path, bin_path: Path):
    try:
        cmd = [COMPILER, *COMP_FLAGS, "-o", str(bin_path), str(src_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)

        if result.returncode != 0:
            fail_log.write(f"[FAIL] {src_path} → {result.stderr}\n")
            return False

        success_log.write(f"[OK] {src_path}\n")
        return True

    except subprocess.TimeoutExpired:
        fail_log.write(f"[TIMEOUT] {src_path}\n")
        return False
```

With that, we can move on to our CSV parsing, where we will write the new C++ file and compile it together, storing the binaries in the same format (with a directory for each user). For now, we only take the first 100 entries to create a subset of the actual dataset (which contains over 50,000 files).

```py
def parseCSV():
    print("Starting CSV Parsing & Compilation...")

    with open(CSV_PATH, newline='', encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        success_count = 0

        for i, row in enumerate(tqdm(reader, total=NUM_FILES, desc="Files Read")):

            if i == NUM_FILES:
                break
        
            username = row['username']
            file_id = row['file']
            source_code = row['flines']
            file_name = row['full_path']

            out_dir = OUTPUT_SRC_DIR / username
            out_dir.mkdir(parents=True, exist_ok=True)

            if file_name.lower().endswith(".cpp"):
                ext = ".cpp"
            else:
                ext = ".txt"  # default fallback

            src_path = out_dir / f"{file_id}{ext}"

            with open(src_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            bin_out_dir = OUTPUT_BIN_DIR / username
            bin_out_dir.mkdir(parents=True, exist_ok=True)
            bin_path = bin_out_dir / f"{file_id}.bin"

            if compile_source(src_path, bin_path):
                success_count += 1

        print(f"Successfully compiled {success_count} of {NUM_FILES} files.")
```

== Appendix

=== Project Structure

*`documents/`* -- Contains all documents and media for the main report, including the `main.typ` for report editing, `refernces.bib` containg all BibTeX references, a Jupyter Notebook for testing the binary feature extraction, as well as the project plan.

*`product/`* -- Contains all files relating to coding aspects of the project.
#list(
    marker: [],
    [*`binary-feature-extraction/`* -- Files relating to the binary feature aspect of the project.],
    indent: 0.4cm,
)
#list(
    marker: [],
    [*`examples/`* -- Contains C source code and compiled ELF files used in testing the binary feature extraction scripts],
    [*`scripts/`* -- The Python scripts used in testing the binary feature extraction. All scripts are also displayed in the report],
    [*`tool/`* -- Contains a combination of testing scripts to make a function feature extraction tool],
    indent: 1cm,
)
#list(
    marker: [],
    [*`machine-learning/`* -- Contains all files relating to the machine learning aspect of the project.],
    indent: 0.4cm,
)
#list(
    marker: [],
    [*`dataset-generation/`* -- Contains all files and directories pertaining to the generation of a dataset for the machine learning model.],
    indent: 1cm,
)
#list(
    marker: [],
    [*`scripts/`* -- Testing scripts used in the examples within the report],
    [*`tool/`* -- Contains a combination of the testing scripts, with a bit of polish, to store a unified script for generating a dataset from the CSV file],
    indent: 1.6cm,
)
#list(
    marker: [],
    [*`model/`* -- Contains all code and files pertaining to the machine learning model used for the project.],
    indent: 1cm,
)

=== Summary of Completed Work



#pagebreak() 
#bibliography("references.bib")