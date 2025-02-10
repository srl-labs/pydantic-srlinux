# revert configs on srl1 and srl2 to the intial state
for name in srl1 srl2 
do
    sudo docker exec ${name} sr_cli /tools system configuration checkpoint clab-initial revert &
done

wait