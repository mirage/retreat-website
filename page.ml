let header t =
  Printf.sprintf
    {|<title>%s</title>
 <meta charset="UTF-8"/>
      <style>
body {
 font-family: monospace;
 color: #333;
 margin: 2%% 0 10%% 15%%;
 width: 45%%;
}
 a, a:visited {
 color: #333;
 text-decoration: none;
 font-weight: bold;
}
    </style>|} t

let content =
  Cmarkit_html.of_doc ~safe:false (Cmarkit.Doc.of_string
{___|# 15th MirageOS hack retreat

We invite you to participate in the fifteenth [MirageOS](https://mirageos.org) hack retreat!
The goal is to sync various MirageOS subprojects, start new ones, and fix bugs.

* *When?* May 13th (arrival) - 20th (departure) 2025
* *Where?* Marrakesh, Morocco
* *Travelling information* Please check travel restrictions from your country to Morocco before registering.
* *How much?* 550 EUR<sup>&#9733;</sup> (10% discount for early birds if you register and pay before March 1st), accommodation and food (full board) included. No refunds possible.
* *How do I register?* Register by sending a mail to <retreat@mehnert.org> **before April 1st, 2025** including:
   * How you became interested in MirageOS;
   * Previous experience with MirageOS and OCaml (no upfront experience required);
   * Project(s) you're interested to work on; and
   * Dietary restrictions
* *Who should participate?* Everybody interested in advancing MirageOS.
* *How big?* We have only limited space (25 people).  Selection will be done by various diversity criteria.
* *How should I behave while there?* Be kind and empathetic to others; do not harrass or threaten anyone. If you make others unsafe, you may be asked to leave.

<sup>&#9733;</sup>: If you cannot afford this, please contact us directly.

<br/>

More information
* Once you've signed up, you will subscribed to the participants mailing list.
* You can work on anything but if you need inspiration, browse the [open issues](https://github.com/search?q=is%3Aopen+org%3Amirage&type=issues).
* The nearest airport is [Marrakesh Menara Airport (RAK)](https://en.wikipedia.org/wiki/Marrakesh_Menara_Airport).  There is also Marrakesh Railway Station (train service from and to Tangier, reachable from Spain by ferry).
* From airport or railway station, take a cab to **Jemaa el-Fnaa** (city centre).
* Follow the [map](https://raw.githubusercontent.com/mirage/marrakech2017/master/data/map.jpg), the address is **27 Derb el Ferrane Azbezt**.
* A [video](https://www.youtube.com/watch?v=zgzwmyxlKBE) contains detailed descriptions.
* We are also happy to pick you up at Jemaa el-Fnaa (phone number will be provided once you registered).

Previous retreats:
* 14th April 22nd - 28th 2024 in Marrakesh, reports: [Hannes](https://hannes.robur.coop/Posts/Retreat2024)
* 13th November 20th - 26th 2023 in Marrakesh (cancelled due to lack of registrations)
* 12th May 1st - 7th 2023 in Marrakesh, reports: [Reynir](https://reyn.ir/posts/2023-05-17-banawa-chat.html) [Romain](https://blog.osau.re/articles/mirageos_retreat.html) [Antonin, Isabella, Fabrice, Christiano, Jules, Paul-Elliot, Sonja](https://tarides.com/blog/2023-07-27-reflections-on-the-mirageos-retreat-in-morocco/)
* 11th October 3rd - 9th 2022 in Mirleft, reports: [Raphaël Proust](https://raphael-proust.gitlab.io/code/mirage-retreat-2022-10.html) [Jules, Sayo, Enguerrand, Sonja, Jan, Lucas](https://tarides.com/blog/2022-10-28-the-mirageos-retreat-a-journey-of-food-cats-and-unikernels) [Pierre](http://blog.enssat.fr/2022/10/pierre-alain-enssat-teacher-at-11th.html) [mirage.io](https://mirage.io/blog/2022-11-07.retreat)
* 10th November 8th - 14th 2021 in Mirleft (cancelled due to Covid19)
* 9th March 13th - 19th 2020 in Marrakesh (partially cancelled due to Covid19)
* 8th September 23rd - 29th 2019 in Marrakesh, reports: [curtisanne (OpenLab Augsburg), in german](https://openlab-augsburg.de/2019/10/lablinked-marrakesh-mirageos-retreat/) [comparing type classes with modules by mark karpov](https://markkarpov.com/post/what-does-a-humped-critter-have-to-teach-us.html)
* 7th March 6th - 13th 2019 in Marrakesh, reports: [report](https://mirage.io/blog/2019-spring-retreat-roundup) [lynxis](https://lunarius.fe80.eu/blog/mirageos-2019.html) [gabriel](http://gallium.inria.fr/blog/marrakesh-retreat-03-2019/) [tarides](https://tarides.com/blog/2019-05-06-7th-mirageos-hack-retreat.html)
* 6th October 3rd - 10th 2018 in Marrakesh
* 5th March 7th - 18th 2018 in Marrakesh, reports: [linse](https://linse.me/2018/04/20/Visiting-the-camels.html), [peter](https://mirage.io/wiki/arm64)
* 4th November 29th - December 6th 2017 in Marrakesh, reports: [mirage](https://mirage.io/blog/2017-winter-hackathon-roundup)
* 3rd March 1st - 8th 2017 in Marrakesh, reports: [mirage](https://mirage.io/blog/2017-march-hackathon-roundup), [reynir](http://reyn.ir/posts/2017-03-20-11-27-Marrakech%202017.html), [olle](http://ollehost.dk/blog/2017/03/17/travel-report-mirageos-hack-retreat-in-marrakesh-2017/)
* 2nd 13th July 2016 at Darwin College in Cambridge, [report](https://mirage.io/blog/2016-summer-hackathon-roundup)
* 1st March 11th - 16th 2016 in Marrakesh, [report](https://mirage.io/blog/2016-spring-hackathon)
|___})

let rendered =
  let hdr = header "MirageOS hack retreats"
  and body = content
  in
  Cstruct.of_string
    (String.concat "" [ "<html><head>" ; hdr ; "</head><body>" ; body ; "</body></html>" ])
