module Main where

import MyLib (createContext, verify)

main :: IO ()
main = do
  x <- createContext verify
  print x
