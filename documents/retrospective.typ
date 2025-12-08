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
  body,
) = {
  // === DOCUMENT SETUP ===
  set document(title: [#title], author: author)
  set text(font: "Nimbus Sans")
  set par(justify: true)
  set list(indent: 0.6cm)
  show link: underline
  show raw: set text(font: "CaskaydiaCove NFM", weight: "regular")
  show raw.where(block: true): set block(inset: 2.5em)


  // === HEADING STYLES ===
  show heading: set block(above: 30pt, below: 30pt)

  // Chapter-level headings
  show heading.where(level: 1): set text(size: 20pt)
  show heading.where(level: 1): set heading(supplement: [Section])
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
  set page(header: context { if counter(page).get().first() > 1 [#report_type #h(1fr) #author] })


  // === FRONT PAGE ===
  set align(center)

  text(22pt, "Final Year Project")
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
  title: "Retrospective Report",
  author: "Luka van Rooyen",
  course_name: "BSc Computer Science (Information Security)",
  supervisor: "Dr. Rachel Player",
  date: "October 2025",
  references: "references.yml", // Specify bibliography file here
)

= Timeline

*Weeks 1-2*
#line()
Initially, my project went very smoothly, and I was able to follow the plan laid out in the preliminary report. By October 10#super[th], I was able to perform all readings, gathering a general understanding of the concepts I would be using throughout the project, as well as completing the project report.

*Weeks 3-5*
#line()
By October 24#super[th], I had begun work on the author attribution report, however was unable to start work on binary feature extraction as the foundation knowledge was a lot more in-depth than I had originally anticipated. I also had difficult coursework for other modules which led to less work overall being done on the project.

*Weeks 6-8*
#line()
By November 7#super[th], I was only able to get some rudimentary binary features working, only able to extract the raw binary. I ran into several complications with different binary formats and compiler artifacts, which left me stuck. As well as this, my knowledge on the subject was not sufficient for the tasks I was trying to implement, so I had to do a lot of additional research online and experiments. This meant I was far behind where I planned to be in my preliminary plan, where I had intended to have a fully functioning binary extraction tool.

*Weeks 9-11*
#line()
By November 21#super[st], I had made significant progress with my binary feature extraction tool, implementing N-gram extraction, instruction frequencies and control flow features. I also began some fundamental work on the machine learning, which put me back on schedule.

*Weeks 12-14*
#line()
By December 5#super[th], I had completed most intended objectives, by having some crude machine learning experiments implemented and a tool to extract a dataset from a publicly available library. Making this tool took a lot more time than expected, so I did not get as far as I would have liked.

*Week 15*
#line()
I had to abandon the machine learning development, as I had to complete my interim report and other additional submissions, so was not able to get a high-accuracy model.

= Second Term Plan

= Reflection

Although I ended up with a product I am very happy with overall, I think several improvements can be made going into next term. One of the main inhibitors of progress was getting stuck on very specific topics for extended periods. For example, when generating a dataset, it took a week of hard work to simply get the tool working, meaning I could not work on anything else in that time, even though it was a minute aspect of the project. This also occurred in the binary feature extraction section, as I focused on one feature at a time rather than planning the features in advance. Another issue that arose was that I was not using issues as effectively as I would have liked to, only making vague statements that I did not really fulfill.

Moving forward, I intend to plan out the programming aspect more, so I can switch between concepts if one proves to more difficult. This parallel development will ensure progress stays maintainable and consistent throughout. I will also use the issue tracking system in Gitlab to keep track of my completed work, and what tasks I have yet to complete.

= Risk Assessment