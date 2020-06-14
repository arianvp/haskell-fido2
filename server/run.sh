#!/usr/bin/env bash
git ls-files .. | entr -r cabal run server
