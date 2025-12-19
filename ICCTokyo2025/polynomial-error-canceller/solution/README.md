# polynomial error canceller

# 日本語(Japanese)

* 作問者: kurenaif
* 想定難易度: easy
* カテゴリ: Crypto
* キーワード: FFT, polynomial

## 概要

これはFFTを利用した畳み込み演算の効率化と周波数成分の取扱についての問題です。
普段はsagemathなどで多項式演算はブラックボックス化されていますが、そこについて深堀りしてみました。

2ステップで構成されていますが、問題全体を通じて以下の共通の仕様があります。

* 512bit以上の `p` を外部から与えることができる。GF(p)上で計算を行う。
* 周波数は2のべき乗である
* `n = 2^14 = 16384` である

### Step1: 各周波数ごとの振幅の検出

このStepでは、2のべき乗の周波数の、ランダムな振幅を持つ波を複数足し合わせた結果が与えられます。その結果から、波と振幅を復元する問題です。

今回は実数ではなく、 `GF(p)` に対して特定しなければなりません。
ここでpを `a*2^b + 1` の形にすることで、FFTができるように準備します。

すると特定の周波数成分だけが出てくるので、その成分だけを抽出し、invFFTをかけることで、その周波数成分の波に戻すことができます。

その振幅を答えると解くことができます。

### Step2: 特定の周波数成分だけを除去する多項式演算

この問題の概要は以下のとおりです。

1. Step1と同じ要領で波を生成する。数列を多項式とみなし、 `e` とする。
2. 除去する周波数成分をサーバーから指定される。それを `e2` とする
3. クライアントからkを受け取り、 `e*k - e2 mod x^n - 1 = 0` であればOK.

多項式演算自体は行列で表現できるので、線形代数でも解けますが、n=16384と大きな値なので
計算量が多すぎて間に合いません。
しかし、 `mod x^n-1` の計算は循環畳み込みになりますので、こちらもFFTで効率的に計算することができます。

`FFT(e*k) = FFT(e) ⊙ FFT(k)` (ここで⊙は要素ごとの積) になることから、 `FFT(k)` には残したい周波数成分を1、残りを0としたものを設定すればうまく動くことがわかります。
そうして求めた `FFT(k)` を invFFT することで、欲しい多項式を得ることができます。

# English

* Author: kurenaif
* Intended difficulty: easy
* Category: Crypto
* Keywords: FFT, polynomial

## Overview

This is a problem about using FFT to speed up convolution and to manipulate frequency components.
Normally in SageMath, polynomial operations are treated as a black box, but here we dig into what’s actually happening.

The challenge has 2 steps, but the following specifications are common to the whole problem:

* You can supply a prime p of at least 512 bits from outside. All computations are done over `GF(p)`.
* Frequencies are powers of two.
* n = 2^14 = 16384.

### Step 1: Detecting the amplitude of each frequency

In this step, you are given the sum of several waves whose frequencies are powers of two, each with a random amplitude. From that result, you must recover the waves and their amplitudes.

This time we’re not working over the reals, but over `GF(p)`, so you must determine the amplitudes in that field.
By choosing p in the form `a*2^b + 1`, you can prepare the field so that FFT is possible.

Then, since only specific frequency components appear, you can extract just that component and apply the inverse FFT to get back the wave corresponding to that frequency.

If you answer the amplitude, you clear this step.

### Step 2: Constructing a polynomial that cancels specific frequency components

This step works as follows:

Generate the wave in the same way as in Step 1, and treat the sequence as a polynomial e.

The server specifies the frequency components to keep/remove; let the target be e2.

The client sends a polynomial `k`, and if `e*k - e2 mod x^n - 1 = 0`, it’s accepted.

In principle, you could model polynomial multiplication as a matrix and solve it with linear algebra, but since `n = 16384` is large, the computation is too heavy.

However, computation modulo `x^n - 1` is a cyclic convolution, so this can also be handled efficiently with FFT.

Since
`FFT(e*k) = FFT(e) ⊙ FFT(k)` (⊙ = elementwise product),
you can make it work by setting `FFT(k)` to 1 on the frequency components you want to keep, and 0 on the others.
Then, by applying inverse FFT to that `FFT(k)`, you get the polynomial you need.