rule Hello 
{ 
  strings: 
    $ascii = "hello";

  condition: 
    $ascii 
}
