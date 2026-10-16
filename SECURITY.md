# Responsible use and disclosure

This project describes a denial-of-service technique against shared LoRaWAN networks so that operators and
network-server developers can defend against it. All results come from simulation; nothing in this repository
transmits on a radio.

- Do not run the attack on a network you do not operate or have written permission to test. Transmitting on
  licence-exempt bands is still regulated, and denying service to city infrastructure can be a crime.
- The simulator contains no code that talks to a real radio, gateway or network server, and we will not accept
  contributions that add one for the attack side.
- We are informing the maintainers of ChirpStack and The Things Stack, whose default settings we model, before the
  paper is published.

If you find a related weakness in a network server or in this code, please contact the maintainers privately
(lohithsaiandra18@gmail.com) before opening a public issue.
