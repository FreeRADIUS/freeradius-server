# Dictionary tests

These files in this directory are all stand-alone dictionary files.
They should all have a common format:

```
BEGIN PROTOCOL Test 99
... test contents
END PROTOCOL Test
```

The only input file should be "base.txt".  That just makes it clearer
where the real tests are: the "*.dict" files.
