package page

import "testing"

func TestCloseFragment(t *testing.T) {
	for in, want := range map[string]string{
		`<div class="a">hi`:                     `<div class="a">hi</div>`,
		`<p>one<b>two</p>`:                      `<p>one<b>two</b></p>`,
		`</div></body></html>text`:              `text`,
		`<script>if (a<b) {`:                    `<script>if (a<b) {</script>`,
		`<style>p{}</style><img src=x>`:         `<style>p{}</style><img src=x>`,
		`<!-- open`:                             `<!-- open-->`,
		`<svg><path d="M0"/></svg>`:             `<svg><path d="M0"/></svg>`,
		`a < b`:                                 `a &lt; b`,
		`<span title="a>b">x</span>`:            `<span title="a>b">x</span>`,
		`ok<plaintext>rest`:                     `ok`,
		`<body><textarea>`:                      `<textarea></textarea>`,
		`<template><div></template>`:            `<template><div></div></template>`,
		`<SCRIPT>x</SCRIPT>`:                    `<SCRIPT>x</script>`,
		`<div><a href="/">x</a></div><br><hr/>`: `<div><a href="/">x</a></div><br><hr/>`,
		`<ul><li>one<li>two</ul>`:               `<ul><li>one<li>two</li></li></ul>`,
		`<iframe src="x">`:                      `<iframe src="x"></iframe>`,
		`<div`:                                  ``,
	} {
		if got := CloseFragment(in); got != want {
			t.Errorf("CloseFragment(%q) = %q, want %q", in, got, want)
		}
	}
}
