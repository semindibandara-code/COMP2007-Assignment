# Name - M.V.R.T.Semindi K. Bandara
# Student ID - 22944368
# COMP2007 Programming Languages Assignment

# Network Access Control & Traffic Rule Evaluation Engine (COMP2007)

# Problem Domain & Scope
This codebase implements a unified Network Access Control and Traffic Rule Evaluation Engine in Lua (1993). It illustrates all nine unit characteristics—including metatable 
abstraction, functional protected calls, first-class rule registration, and safe multiple-return parsing—within a single, coherent domain.

# Project Structure
   **firewall_engine.lua** - Modular domain library containing the Packet prototype,encapsulated rule engine, and exception-protected log parsing routines.
   **main.lua** - Primary executable driver script running rule registration, ingress network stream processing, error recovery, and traffic metrics computation.

# Dependencies
  Standard Lua runtime (`lua` 5.1, 5.2, 5.3, 5.4 or `luajit`).
  Zero external C-libraries or third-party dependencies required.

# Compilation and Execution
lua main.lua

