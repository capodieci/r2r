<?php
// Reusable animated network-mesh SVG. Include with `require`/`include`.
// Adapted from the top-part of the Sippis logo — nodes glow in, links draw
// themselves, and orange packets hop between nodes to depict onion routing.
//
// The animation only runs once per page load (packets fire twice then stop
// via `.pw` opacity 0 at 8s), so it's decorative rather than distracting.
?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="118 45 360 250" width="360" height="250" aria-label="R2R decentralised mesh: independent relays gossip and route encrypted payloads with no central server." role="img">
  <defs>
    <style><![CDATA[
      @keyframes lineIn  {0%{stroke-dashoffset:300;opacity:0}30%{opacity:.4}100%{stroke-dashoffset:0;opacity:.4}}
      @keyframes lineInA {0%{stroke-dashoffset:300;opacity:0}30%{opacity:.35}100%{stroke-dashoffset:0;opacity:.35}}
      .cn{stroke:#0A7B83;stroke-width:2.5;fill:none;stroke-dasharray:300;stroke-dashoffset:300;animation:lineIn 1.5s ease-out forwards}
      .ca{stroke:#F26430;stroke-width:2;fill:none;stroke-dasharray:300;stroke-dashoffset:300;animation:lineInA 1.5s ease-out forwards}
      .l1{animation-delay:.1s}.l2{animation-delay:.2s}.l3{animation-delay:.3s}
      .l4{animation-delay:.4s}.l5{animation-delay:.5s}.l6{animation-delay:.6s}
      .l7{animation-delay:.7s}.l8{animation-delay:.8s}.l9{animation-delay:.9s}
      .l10{animation-delay:1s}.l11{animation-delay:1.1s}.l12{animation-delay:1.2s}
      .l13{animation-delay:1.3s}.l14{animation-delay:1.4s}.l15{animation-delay:1.5s}
      .l16{animation-delay:1.6s}.l17{animation-delay:1.7s}.l18{animation-delay:1.8s}
      .l19{animation-delay:1.9s}
      @keyframes nIn{0%{opacity:0;transform:scale(0)}60%{opacity:1}80%{transform:scale(1.15)}100%{opacity:1;transform:scale(1)}}
      .np{fill:#0A7B83;opacity:0;transform-box:fill-box;transform-origin:center;animation:nIn .6s ease-out forwards}
      .ns{fill:#0EADB5;opacity:0;transform-box:fill-box;transform-origin:center;animation:nIn .6s ease-out forwards}
      .na{fill:#F26430;opacity:0;transform-box:fill-box;transform-origin:center;animation:nIn .6s ease-out forwards}
      .n1{animation-delay:.3s}.n2{animation-delay:.5s}.n3{animation-delay:.7s}
      .n4{animation-delay:.9s}.n5{animation-delay:1.1s}.n7{animation-delay:1.5s}
      .n8{animation-delay:1.7s}.n9{animation-delay:1.9s}.n10{animation-delay:2.1s}
      .n11{animation-delay:2.3s}.n12{animation-delay:2.5s}.n13{animation-delay:2.7s}
      @keyframes coreL{0%{r:0;opacity:0}8%{r:18;opacity:1}20%{r:21}32%{r:18}44%{r:21}56%{r:18}68%{r:20}80%{r:18}100%{r:18;opacity:1}}
      @keyframes ringL{0%{r:0;opacity:0}8%{r:10;opacity:.6}20%{r:13;opacity:.3}32%{r:10;opacity:.6}44%{r:13;opacity:.3}56%{r:10;opacity:.6}68%{r:11;opacity:.5}80%{r:10;opacity:.6}100%{r:10;opacity:.6}}
      .corN{fill:#0A7B83;opacity:0;animation:coreL 7s ease-in-out 1.3s forwards}
      .corR{opacity:0;animation:ringL 7s ease-in-out 1.3s forwards}
      @keyframes sI4{0%{opacity:0;transform:scale(0)}100%{opacity:.4;transform:scale(1)}}
      @keyframes sI3{0%{opacity:0;transform:scale(0)}100%{opacity:.3;transform:scale(1)}}
      .s4{opacity:0;transform-box:fill-box;transform-origin:center;animation:sI4 .6s ease-out forwards}
      .s3{opacity:0;transform-box:fill-box;transform-origin:center;animation:sI3 .6s ease-out forwards}
      .d1{animation-delay:2s}.d2{animation-delay:2.2s}.d3{animation-delay:2.4s}
      .d4{animation-delay:2.6s}.d5{animation-delay:2.8s}.d6{animation-delay:3s}
      @keyframes pkG{0%{offset-distance:0%;opacity:0}5%{opacity:1}95%{opacity:1}100%{offset-distance:100%;opacity:0}}
      @keyframes pkF{0%,75%{opacity:1}100%{opacity:0}}
      .pk{fill:#F26430;offset-rotate:0deg;opacity:0}
      .pa{animation:pkG 2.5s linear 1.8s 2}
      .pb{animation:pkG 3s linear 2.2s 2}
      .pc{animation:pkG 2.8s linear 2.5s 2}
      .pd{animation:pkG 3.2s linear 1.9s 2}
      .pe{animation:pkG 2.2s linear 2.8s 2}
      .pw{animation:pkF 8s ease-out forwards}

      /* R2Я wordmark overlay — sits on top of the animated mesh */
      @keyframes wmIn{0%{opacity:0;transform:scale(0.85)}100%{opacity:1;transform:scale(1)}}
      .wm{
        font: 800 130px/1 -apple-system, "Segoe UI", system-ui, sans-serif;
        letter-spacing:-10px; fill:#fff;
        transform-box:fill-box; transform-origin:center;
        animation: wmIn 1.2s ease-out .2s both;
      }
      .wm .accent{fill:#0EADB5}
    ]]></style>
    <filter id="wm-shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur in="SourceAlpha" stdDeviation="4"/>
      <feOffset dx="0" dy="3" result="off"/>
      <feFlood flood-color="#000" flood-opacity="0.55"/>
      <feComposite in2="off" operator="in"/>
      <feMerge>
        <feMergeNode/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>

  <g transform="translate(300, 170) rotate(90)">
    <line class="cn l1"  x1="-60" y1="-150" x2="20"  y2="-110"/>
    <line class="cn l2"  x1="20"  y1="-110" x2="80"  y2="-145"/>
    <line class="cn l3"  x1="-60" y1="-150" x2="-30" y2="-90"/>
    <line class="cn l4"  x1="20"  y1="-110" x2="-30" y2="-90"/>
    <line class="cn l5"  x1="-30" y1="-90"  x2="-80" y2="-30"/>
    <line class="ca l6"  x1="80"  y1="-145" x2="40"  y2="-40"/>
    <line class="cn l7"  x1="-30" y1="-90"  x2="40"  y2="-40"/>
    <line class="cn l8"  x1="-80" y1="-30"  x2="0"   y2="0"/>
    <line class="cn l9"  x1="40"  y1="-40"  x2="0"   y2="0"/>
    <line class="ca l10" x1="-80" y1="-30"  x2="-40" y2="40"/>
    <line class="cn l11" x1="0"   y1="0"    x2="80"  y2="30"/>
    <line class="cn l12" x1="0"   y1="0"    x2="-40" y2="40"/>
    <line class="cn l13" x1="80"  y1="30"   x2="30"  y2="90"/>
    <line class="ca l14" x1="-40" y1="40"   x2="-20" y2="110"/>
    <line class="cn l15" x1="80"  y1="30"   x2="60"  y2="150"/>
    <line class="cn l16" x1="30"  y1="90"   x2="-20" y2="110"/>
    <line class="cn l17" x1="-20" y1="110"  x2="60"  y2="150"/>
    <line class="cn l18" x1="30"  y1="90"   x2="60"  y2="150"/>
    <line class="cn l19" x1="-20" y1="110"  x2="-80" y2="145"/>

    <g class="pw">
      <circle class="pk pa" r="3"   style="offset-path:path('M-60,-150 L20,-110 L-30,-90 L0,0')"/>
      <circle class="pk pb" r="3"   style="offset-path:path('M80,-145 L40,-40 L0,0 L80,30 L60,150')"/>
      <circle class="pk pc" r="3"   style="offset-path:path('M0,0 L-40,40 L-20,110 L-80,145')"/>
      <circle class="pk pd" r="2.5" style="offset-path:path('M-80,-30 L0,0 L80,30 L30,90')"/>
      <circle class="pk pe" r="2.5" style="offset-path:path('M-60,-150 L-30,-90 L-80,-30 L-40,40 L-20,110')"/>
    </g>

    <circle class="np n1"  cx="-60" cy="-150" r="14"/>
    <circle class="ns n2"  cx="20"  cy="-110" r="10"/>
    <circle class="np n3"  cx="80"  cy="-145" r="11"/>
    <circle class="ns n4"  cx="-30" cy="-90"  r="8"/>
    <circle class="na n5"  cx="40"  cy="-40"  r="9"/>
    <circle class="corN"   cx="0"   cy="0"    r="18"/>
    <circle class="corR"   cx="0"   cy="0"    r="10" fill="none" stroke="#fff" stroke-width="2"/>
    <circle class="ns n7"  cx="-80" cy="-30"  r="10"/>
    <circle class="ns n8"  cx="80"  cy="30"   r="10"/>
    <circle class="na n9"  cx="-40" cy="40"   r="9"/>
    <circle class="ns n10" cx="30"  cy="90"   r="8"/>
    <circle class="np n11" cx="-20" cy="110"  r="10"/>
    <circle class="np n12" cx="60"  cy="150"  r="14"/>
    <circle class="ns n13" cx="-80" cy="145"  r="11"/>

    <circle class="s4 d1" cx="-95"  cy="-160" r="3" fill="#0EADB5"/>
    <circle class="s4 d2" cx="105"  cy="-155" r="3" fill="#0EADB5"/>
    <circle class="s4 d3" cx="-105" cy="155"  r="3" fill="#F26430"/>
    <circle class="s4 d4" cx="85"   cy="165"  r="3" fill="#0EADB5"/>
    <circle class="s3 d5" cx="110"  cy="10"   r="4" fill="#0A7B83"/>
    <circle class="s3 d6" cx="-110" cy="-10"  r="4" fill="#0A7B83"/>
  </g>

  <!-- R2Я wordmark, centered on top of the mesh -->
  <text class="wm" x="298" y="215" text-anchor="middle" filter="url(#wm-shadow)">R<tspan class="accent">2</tspan>Я</text>
</svg>
