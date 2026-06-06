---
layout: post
title: "ufo-sightings"
date: 2026-06-06
categories: [OSINT]
difficulty: Easy
platform: UNbreakable Romania 2026
tags: [google-lens, maps, geolocation]
excerpt: "Geolocating a roadside UFO advertisement with Google Lens, then mapping the coordinates for the answer."
---

## Summary

This was a straightforward geolocation challenge. The only input was an image, and the goal was to identify the place it was taken and turn that location into the requested coordinate format.

I used reverse image search to identify the sign, then moved to Google Maps to pin down the exact spot.

## Analysis

Google Lens pointed me to articles about a UFO-themed roadside advertisement in the Czech Republic. That led to a location search on Maps using the phrase `mattoni ufo`, which quickly narrowed down the correct place.

Once the location was confirmed, the remaining step was simply extracting coordinates in the required format.

The image used during the solve:

![Mattoni UFO location]({{ '/assets/img/unr26/ufo-mattoni.png' | relative_url }})

## Exploitation

The solve path was:

1. Reverse image search the supplied photo.
2. Confirm the object in articles and forum posts.
3. Search the matching place in Google Maps.
4. Read the coordinates from the map pin.
5. Submit the coordinates as the flag.

Useful references found during the search:

```text
https://tachovsky.denik.cz/zpravy_region/podivejte-se-u-dalnici-na-tachovsku-pristava-ufo-20210721.html
https://www.reddit.com/r/czech/comments/1j6c5g4/what_is_that/
https://maps.app.goo.gl/5wJzE7qhzyADv5FT7
```

## Flag

`UNR{49.740,12.755}`
