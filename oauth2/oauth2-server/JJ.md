## main bookmark(=branch) を push
```sh
jj git push -b main (--bookamark main)
```

## bookmark を移動

```
jj b set main -r @
```


## 1操作戻す

```sh
jj undo
```




## new

```sh
jj new 
```

```sh
jj new main
```

```sh
jj new main -m "message"
```


## desc

```
jj desc -m "change message"



## commit

desc + new = commit

```sh
jj commit -m "message"
```


## rebase

```
jj rebase -d main
```
