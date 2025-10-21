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

The problem of attributing a piece of code, particularly a binary file, to a known author using machine learning is complex and must be decomposed into several logical steps#super[@rosenblum2011wrote]. Moreover, the issue has applications in both malware forensics#super[@ALRABAEE2014S94] and threat detection, as it allows us to automatically identify and categorise malicious code authors#super[@10.11453292577]. This project explores predicting authorship by extracting and analysing features from compiled code and training machine learning models to interpret these features, assessing whether extracted features correspond to known malicious code or authors. The early objectives include: reviewing existing techniques for binary feature extraction, building a dataset of binaries from multiple authors, implementing and testing preliminary machine learning classifiers on extracted features, and evaluating early test results and refining the approach accordingly. The ultimate goal of the project is to evaluate whether distinctive patterns and features in compiled binaries can be analysed for reliable authorship attribution via machine learning methods. In doing so, we can determine whether the features of the binary are indicative of malicious code or known malicious authors.

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
- Explore supplementary readings using Google scholar to find academic literature on binary feature extraction and control graphs#super[@theiling2000extracting]
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
- Familiarise myself with machine learning techniques in Python (particularly using the `scikit-learn` library#super[@pedregosa2011scikit]) and build a plan for my machine learning algorithm
*Deliverables:*
- A successful binary feature extraction tool
- A completed binary feature extraction report
- A plan for the machine learning aspect of the project
#linebreak()
*Weeks 9-11* (_November 10#super[th] - November 21#super[st]_)
#line(length: 100%, stroke: 0.5pt)
- Locate open source datasets that can be used in training (such as from the Google Code Jam#super[@caliskan2015anonymizing])
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

== Introduction

In this section, I will explore the theories and practices pertaining to the attribution of a piece of code to a known author. While not all these methods are easily measurable in the context of machine learning, the underpinning concepts will heavily influence my approach to author attribution. Abstractly, the process involves identifying an author's "fingerprint", and using syntactic identifiers in their writing style in order to determine whether a piece of code fits their respective fingerprint. In the context of computer security, accurately and reliably identifying adversaries is a very desirable goal#super[@10.11453292577]. This capability not only supports forensic investigations and accountability but may also serve as a deterrent to future attacks by reducing the perceived anonymity of adversaries. In this report, I will delve into some objectives that author attribution aims to achieve, some metrics that can be used for identifying authors, then putting these metrics in context and evaluating their relevance to this project's goals and technical implementation.

== Objectives of Author Attribution

The following objectives are derived from V. Kalgutar et al.'s article "Code Authorship Attribution: Methods and Challenges"#super[@10.11453292577], and I believe they concisely represent the core goals of authorship attribution. Their descriptions have been paraphrased for clarity.

#list([_*Authorship Identification*_ - find the most likely author of a specific work from a set of given candidate authors.],[_*Authorship Clustering*_ - grouping works based on stylistic similarities to identify groups in which an author has collaborated.],
[_*Authorship Evolution*_ - analysing changes in an author's code style; the way their programming skills, preferences, and writing style evolve over a period of time.],
[_*Authorship Verification*_ - determining the author of a given piece of code, to ensure that innocent code has not been tampered with by malicious authors.], indent: 0.6cm, spacing: 0.4cm, marker: [--])


== Code Author Analysis Metrics

Now that the goals and motivations have been established, we focus now on how exactly we can measure coding style. 

== Applicable Metrics in the Context of Machine Learning

== Conclusion


#pagebreak()

= Binary Feature Extraction
#pagebreak()

= Machine Learning
#pagebreak() 
#bibliography("references.bib")