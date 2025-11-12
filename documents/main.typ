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
  
  // === PAGE SETUP ===
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

= Preliminary Project Plan

== Abstract

The problem of attributing a piece of code, particularly a binary file, to a known author using machine learning is complex and must be decomposed into several logical steps @rosenblum2011. Moreover, the issue has applications in both malware forensics @alrabee2014 and threat detection, as it allows us to automatically identify and categorise malicious code authors @kalgutkar2019. This project explores predicting authorship by extracting and analysing features from compiled code and training machine learning models to interpret these features, assessing whether extracted features correspond to known malicious code or authors. The early objectives include: reviewing existing techniques for binary feature extraction, building a dataset of binaries from multiple authors, implementing and testing preliminary machine learning classifiers on extracted features, and evaluating early test results and refining the approach accordingly. The ultimate goal of the project is to evaluate whether distinctive patterns and features in compiled binaries can be analysed for reliable authorship attribution via machine learning methods. In doing so, we can determine whether the features of the binary are indicative of malicious code or known malicious authors.

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
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
\xe0\x05\x00\x00\x00\x00\x00\x00\xe0\x05\x00\x00\x00\x00\x00

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

We can then use this function in conjunction with our extraction code to determine the count of each instruction, and hence the instruction frequency. We can store the counts of each mnemonic using a Python dictionary object.

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

=== Instruction Count Normalisation

The next logical step is to normalise the instruction counts, as some longer binaries may have higher counts of instructios overall, we care about the relative *frequencies* (or ratios) of these instructions. As well as this, some binary files may contain a wider array of instructions, which could skew data if we dynamically inspect the instruction counts. This requires special attention, and for the purposes of the project we will focus on the main instructions that are most common and will lead to more accurate authorship attribution. 

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
        if relevant_instructions[i] in counts:
            c = counts.get(relevant_instructions[i])
            freqs[i] = c / total_instructions
        else:
            freqs[i] = 0

    print(freqs)
```

Performing this on `example1` produces the output:

```
[0.03703704 0.0617284  0.0617284  0.03703704 0.25925926 0.04938272 0.02469136 0.02469136 0.02469136]
```

Which is a `numpy` array of type `float`, containing the frequencies neatly formatted as `numpy` and `sklearn` are extremely compatible. 

#pagebreak()

= Machine Learning
#pagebreak() 
#bibliography("references.bib")