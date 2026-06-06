Skylanders Portal Manager
=========================

What is this?
-------------
Skylanders Portal Hub is a desktop app that lets you load Skylanders
characters onto a virtual portal in Cemu (Wii U emulator) without
needing a physical portal or figures. It works with the VirtPort build
of Cemu (SkylandersVirtualPortal).

Requirements
------------
- Windows 10 or later
- Cemu with the VirtPort / SkylandersVirtualPortal build
- Your Skylanders .bin save files in a folder on your PC
- A controller (Xbox or PlayStation via DS4Windows/Steam Input)
  for the controller wheel feature

First Time Setup
----------------
1. Open Cemu with the VirtPort build first — it must be running
   before you open Skylanders Portal Hub
2. Launch Skylanders Portal Hub
3. Click the Folder button (top right) and point it to your
   folder of Skylanders .bin files
4. VirtPort connects automatically on localhost:5678
   The dot in the top bar turns green when connected

Loading Skylanders
------------------
- Click any Skylander in the list to instantly put them on the portal
- Use the element filter buttons to filter by type
- Use the game tabs (Spyro's Adventure, Giants, etc.) to browse by game
- Star any Skylander to add them to Favorites for quick access
- Slot buttons (1-5) control which portal slot they load into:
    Slot 1 — Core Skylanders
    Slot 2 — Swap Force bottoms
    Slot 3 — Items / Adventure Packs
    Slot 4 — Traps (Trap Team)
    Slot 5 — Vehicles (SuperChargers)

Swap Force
----------
- Use the Swap Force tab to mix and match top and bottom halves
- Save your favourite combinations with the Star button
- Saved combos appear in Favorites > Swap Force Combos

Controller Wheel
----------------
- Press Right Stick (RS) to open the wheel
- Press RS again to cycle through presets
- Use D-pad directions to load the assigned Skylander
- Configure in Settings > Controller > Configure D-pad Bindings
- Create presets grouped by game for quick switching

Global Keybinds
---------------
- Assign keyboard shortcuts to load specific Skylanders
- Works while Cemu is in focus (no need to tab back to the app)
- Configure in Settings > Keybinds
- Can be disabled if you prefer using the controller wheel only

Troubleshooting
---------------
- VirtPort not connecting: Make sure Cemu VirtPort build is open
  before launching the app. Check Settings > Controller for the
  host/port (default: localhost:5678)
- Controller not detected: Go to Settings > Controller and click
  "Pair Controller" to force a rescan
- Check the Debug Log (camera icon in the toolbar) for detailed
  error messages
- Swap Force only loading one half: Use the Swap Force Editor tab
  and save the combo first with the Star button
