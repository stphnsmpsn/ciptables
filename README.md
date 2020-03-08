# Tech Challenge:

Write a C program that can list, add, modify, and delete iptables rules, in multiple chains.

## Setup

* IPTables Version: iptables v1.6.1
* Kernel Version: 4.15.0-1057-aws
* GCC Version: 7.4.0
* Other Libraries: iptables.dev

## How to do this programmatically?

We can do this programmatically by using `libiptc (lip4tc)`!

## API

This program exposes an IptablesInterface with methods to perform the following:
* List Tables
* Create Chains
* Delete Chains
* Append Entries
* Delete Entries
* Replace Entries

This project uses a dependency injection pattern known as a Service Locator to allow overriding the implementation of the interface (usesul for unit testing and keeps things loosely coupled).


The interface defines a contract that the application must implement the following methods: 

1) List Table:
  
    ```
    Iptables()->listTable(tableName);
    ```

   Output: `Iptables()->listTable("filter");`

   ```
    ubuntu@ip-172-31-46-220:~/ciptables/build$ sudo ./ciptables lt filter
    Chain INPUT(policy ACCEPT)
    num target                   prot opt source          destination
    1   ACCEPT                   tcp  --  anywhere        anywhere

    Chain FORWARD(policy DROP)
    num target                   prot opt source          destination
    1   DOCKER-USER              all  --  anywhere        anywhere
    2   DOCKER-ISOLATION-STAGE-1 all  --  anywhere        anywhere
    3   ACCEPT                   all  --  anywhere        anywhere
    4   DOCKER                   all  --  anywhere        anywhere
    5   ACCEPT                   all  --  anywhere        anywhere
    6   ACCEPT                   all  --  anywhere        anywhere

    Chain OUTPUT(policy ACCEPT)
    num target                   prot opt source          destination

    Chain DOCKER
    num target                   prot opt source          destination

    Chain DOCKER-ISOLATION-STAGE-1
    num target                   prot opt source          destination
    1   DOCKER-ISOLATION-STAGE-2 all  --  anywhere        anywhere
    2   RETURN                   all  --  anywhere        anywhere

    Chain DOCKER-ISOLATION-STAGE-2
    num target                   prot opt source          destination
    1   DROP                     all  --  anywhere        anywhere
    2   RETURN                   all  --  anywhere        anywhere

    Chain DOCKER-USER
    num target                   prot opt source          destination
    1   RETURN                   all  --  anywhere        anywhere
   ```

2) Create Chain

    ```
    Iptables()->createChain(tableName, chainName);
    ```

3) Delete Chain

    ```
    Iptables()->deleteChain(tableName, chainName);
    ```

4) Append Rule to Chain:

    ```
    Iptables()->appendRuleToChain(tableName, chainName, entry);
    ```

    The third argument to append is a `const struct ipt_entry const * entry` (a constant pointer to constant data which represents the iptables entry to add to the specified table/chain). Due to time constraints, I did not implement a command line parser for this, but simply use a dummy entry returned by the `GetDummyIptEntry()` utility function. This entry will set the dscp value of tcp packets matching destination port 1111  to 0x1A.

5) Replace Rule in Chain:
    
    ```
    Iptables()->replaceRuleInChain(tableName, chainName, entry, ruleNumber);
    ```

4) Delete Rule From Chain:

    ```
    Iptables()->deleteRuleFromChain(tableName, chainName, ruleNumber);
    ```

 ## Command Line Use

The program also supports execution from the command line. The following commands are supported (Note: the syntax assumes you are running commands from the project root directory immediately after building)

1) List

    ```
    sudo ./build/ciptables lt $tableName
    ```
2) Create Chain

    ```
    sudo ./build/ciptables cc $tableName $chainName
    ```
3) Delete Chain

    ```
    sudo ./build/ciptables dc $tableName $chainName
    ```

4) Append Rule to Chain

    ```
    sudo ./build/ciptables ar $tableName $chainName $port
    ```

3) Replace Rule in Chain
    
    ```
    sudo ./build/ciptables rr $tableName $chainName $port #ruleNumber
    ```

4) Delete Rule From Chain

    ```
    sudo ./build/ciptables dr $tableName $chainName $ruleNumber
    ```

## Building The Application

Convenience scripts are provided for both VSCode and basic bash shell. If using VSCode, simple open the project folder, edit your path to GCC (if necessary) in `tasks.json`, and run using `CTRL + SHIFT + B`. Otherwise, use the convenience script `./build.sh`

### Warnings

The application builds successfully with no errors and no warnings. 

Below is the output of the GCC build:

```
ubuntu@ip-172-31-46-220:~/ciptables$ /usr/bin/gcc -g ./devel/Ciptables.c ./devel/Util.c ./devel/CommandParser.c ./devel/ServiceLocator/Iptables/Iptables.c ./devel/ServiceLocator/Iptables/IptablesImplementation.c ./devel/ServiceLocator/Iptables/NullIptablesImplementation.c ./devel/ServiceLocator/Null/NullFunctions.c -o ./build/ciptables -lip4tc
ubuntu@ip-172-31-46-220:~/ciptables$ 
```

And using the VSCode Build scripts:
```
> Executing task: /usr/bin/gcc -g /home/ubuntu/ciptables/devel/Ciptables.c /home/ubuntu/ciptables/devel/Util.c /home/ubuntu/ciptables/devel/CommandParser.c /home/ubuntu/ciptables/devel/ServiceLocator/Iptables/Iptables.c /home/ubuntu/ciptables/devel/ServiceLocator/Iptables/IptablesImplementation.c /home/ubuntu/ciptables/devel/ServiceLocator/Iptables/NullIptablesImplementation.c /home/ubuntu/ciptables/devel/ServiceLocator/Null/NullFunctions.c -o /home/ubuntu/ciptables/devel/../build/ciptables -lip4tc <


Terminal will be reused by tasks, press any key to close it.
```

## Demonstration Suite

A quick demonstration of the functionality can be run by issuing the following command: 

```
sudo ./build/ciptables rundemo
```

The Output is as shown below: 

```
Step 1: Listing `mangle` Table...


Chain PREROUTING(policy ACCEPT)
num target                   prot opt source          destination

Chain INPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain FORWARD(policy ACCEPT)
num target                   prot opt source          destination

Chain OUTPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain POSTROUTING(policy ACCEPT)
num target                   prot opt source          destination



Step 2: Creating `TEST` chain in `mangle` Table...



Step 3: Listing `mangle` Table (you should see a new 'TEST' chain)...


Chain PREROUTING(policy ACCEPT)
num target                   prot opt source          destination

Chain INPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain FORWARD(policy ACCEPT)
num target                   prot opt source          destination

Chain OUTPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain POSTROUTING(policy ACCEPT)
num target                   prot opt source          destination

Chain TEST
num target                   prot opt source          destination



Step 4: Appending Dummy Rule to 'TEST' Chain in `mangle` Table...



Step 5: Listing `mangle` Table (you should see a new rule in the `TEST` chain)...


Chain PREROUTING(policy ACCEPT)
num target                   prot opt source          destination

Chain INPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain FORWARD(policy ACCEPT)
num target                   prot opt source          destination

Chain OUTPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain POSTROUTING(policy ACCEPT)
num target                   prot opt source          destination

Chain TEST
num target                   prot opt source          destination
1   DSCP                     tcp  --  anywhere        anywhere



Step 6: Deleting Rule from the `TEST` chain in `mangle` Table...



Step 7: Listing `mangle` Table (you should see one less rule in the `TEST` chain)...


Chain PREROUTING(policy ACCEPT)
num target                   prot opt source          destination

Chain INPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain FORWARD(policy ACCEPT)
num target                   prot opt source          destination

Chain OUTPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain POSTROUTING(policy ACCEPT)
num target                   prot opt source          destination

Chain TEST
num target                   prot opt source          destination



Step 8: Deleting `TEST` chain from `mangle` Table...



Step 9: Listing `mangle` Table (you should see one chain in the table)...


Chain PREROUTING(policy ACCEPT)
num target                   prot opt source          destination

Chain INPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain FORWARD(policy ACCEPT)
num target                   prot opt source          destination

Chain OUTPUT(policy ACCEPT)
num target                   prot opt source          destination

Chain POSTROUTING(policy ACCEPT)
num target                   prot opt source          destination
```
