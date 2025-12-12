# My Project Diary

## Entry 25 - 11/12/2025

Recorded my demonstration video and completed my retrospective report and interim report, completeing spelling and grammar checks.

## Entry 24 - 10/12/2025

Cleaned up the project repository to ensure that all files are up to date and complete.

## Entry 23 - 08/12/2025

Updated individual test scripts to output better for the demonstration video, completed the reflection and timeline section of the reflective report.

## Entry 22 - 04/12/2025

Lowered dataset size for testing on my laptop, and added generated files to the gitignore file. Skipped using the GradientBooster classifier in machine learning tests as it takes far too long to cross-validate.

## Entry 21 - 03/12/2025

Revamped the machine learning tests, using the GridSearchCV class and a pipeline to speed up model training.

## Entry 20 - 27/11/2025

Completed the summary of work section for the report, as well as updating the machine learning section with my new machine learning progress.

Updated some tests for the machine learning models, testing some cross-validation methods to see which classifier is best

## Entry 19 - 25/11/2025

Added binary feature extraction tool to the overall dataset generation pipeline, successfully prototyping dataset generation.

## Entry 18 - 24/11/2025

Added a progress bar to the dataset generation tool. This decision came as I wanted to see how fast it runs. However, I noticed it ran very slow so decided to migrate the project from using `pip` to `uv`, a faster package manager. This led to minor improvements, but I beieve the limitation lies in my laptop hardware.

Added sections to my report that are required for the interim report.

## Entry 17 - 21/11/2025

Finished tool for extracting binaries from the CFG. Pausing development of new tools for now, focusing on formatting all my work for the interim report.

## Entry 16 - 20/11/2025

Began work on Machine Learning aspect of the project, as this will be useful going into Term 2. Researched datasets that contain author AND binary files, however all that I found was a CSV file from the Google Code Jam competition. This meant I had to create a tool to extract the source code from the file, as well as create binaries from the extracted source code.

## Entry 15 - 19/11/2025

Paused work on the n-grams, instead working on extracting CFG. Very complicated to implement by hand and my solution will likely be inefficient/slow, so opting to use pre-existing libraries. Managed to do some basic CFG extraction and planning to normalise some features from it.

## Entry 14 - 17/11/2025

Started to implement the n-gram extraction. This is because of its simplicity. While I was able to implement it, I hit a roadblock when trying to normalise the data as I require a whole dataset to do this. I intend to use the sklearn module to do TF-IDF, but this can only be done in conjunction with the machine learning experiments.

## Entry 13 - 12/11/2025

Successfully implemented the instruction frequency part of the the extraction tool. Put the results in a jupyter notebook so that I can analyse and visualise the results when running on some examples. 

## Entry 12 - 10/11/2025

Added some more binary examples, modified some old scripts and implemented successful extraction of the .text section of the binary file. This allowed me to begin working on the instruction counts/frequency without worrying about compiler noise.

## Entry 11 - 06/11/2025

Changed binary examples from Windows .exe files to Linux ELF, as this reduces compiler overhead and have more accessible extraction libraries available.

## Entry 10 - 04/11/2025

Added extraction scripts to get the basic information from a binary file. Encountered some issues when it came to massive instruction sets for basic programs.

## Entry 9 - 29/10/2025

Started basic research into binary feature extraction. Set up some basic experiments on a new branch to ensure that changes can be reverted easily.

## Entry 8 - 27/10/2025

Completed the author attribution report, complete with conclusion and merged into the main branch.

## Entry 7 - 21/10/2025

Conducted additional research into code author analysis metrics. Polished off attribution objectives section with a conclusion. Mostly finished analysis metrics section.

## Entry 6 - 15/10/2025

Began report on author attribution, conducted additional research into objectives of author attribution.

## Entry 5 = 10/10/2025

Completed preliminary project plan and submitted for review.

## Entry 5 - 09/10/2025

Reviewed draft of project plan in context of required deliverables. Added paragraph outlining Term 1 plans, including reports I plan to write.

## Entry 4 - 08/10/2025

Completed abstract, timeline, and risk assessment and mitigations, as well as meeting with supervisor to discuss current draft of report.

## Entry 3 - 06/10/2025

Searched for supplementary sources on binary feature extraction. Set up Typst project where all report-writing will happen. Started developing Term 1 timeline.

## Entry 2 - 01/10/2025

Began researching into recommended sources, drafted rough abstract for Term 1 project plan.

## Entry 1 - 30/09/2025

Initialised project repository and diary.
