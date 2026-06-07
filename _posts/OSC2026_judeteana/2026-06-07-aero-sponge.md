---
layout: post
title: "aero sponge"
date: 2026-06-07
categories: [OSINT]
difficulty: Medium
platform: OSC2026 judeteana
tags: [OSINT, forensics, gps, flight-tracking]
excerpt: "Identifying an aircraft flying over an unlikely location by leveraging image metadata and historical flight tracking data."
---

## Summary

### Challenge Description
 "Vara trecuta, intr-o după-amiază banala cand soarele batea peste casa lui SpongeBob, cineva a făcut o fotografie care ascunde mai mult decât pare la prima vedere. Uneori, cheia nu stă în ceea ce privești, ci în ceea ce se întâmpla exact în acel moment. De ce zboara avioane pe aici? Spongebob locuieste sub apa…

Indentifica avionul care strica linistea locuitorilor din orasul subacvatic unde locuieste SpongeBob.

Flag format: OSC{HexIdAvion_CallSign} De exemplu, pentru zborul de pe 1 Aprilie de la Bucharest, Romania la Larnaca, Cyprus de la ora 11:35AM EEST este OSC{471F62_WMT6320}"

The challenge presents a png image of SpongeBob's neighborhood. The objective is to identify this specific aircraft using geolocation and historical flight telemetry data.

## Analysis 

   The provided file was a PNG image. Initial forensic analysis focused on the embedded EXIF data to determine the time and location the photograph was taken.

![Flight Photo]({{ '/assets/img/osc26j/spongebob.png' | relative_url }})

```bash
exiftool spongebob.png

   Key findings:
 GPS Version ID                  : 2.3.0.0                                                           
 GPS Latitude                    : 44 deg 20' 10.70"                                                 
 GPS Longitude                   : 12 deg 15' 45.60"                                                 
 Create Date                     : 2025:07:20 06:47:30                                               
 Modify Date                     : 2025:07:20 06:47:30 
```

 Geolocating these coordinates revealed that the location corresponds to the Mirabilandia Theme Park in Italy.

## Exploitation

  The picture was taken at the Mirabilandia Theme Park in Italy on 2025:07:20 at 06:47:30. Now, we need to find the flight that went over that exact location at that moment. After some time spent struggling to find a site that could show me the plane, I stumbled upon ADSBExchange, where I found the exact plane and reconstructed the flag.

![Flight Photo]({{ '/assets/img/osc26j/plane.png' | relative_url }})

## Flag

`OSC{4CA9A1_NOS7026}`
