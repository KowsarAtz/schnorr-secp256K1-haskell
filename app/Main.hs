module Main where

import qualified MyLib (greet)

main :: IO ()
main = MyLib.greet
