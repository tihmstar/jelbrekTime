//
//  ViewController.m
//  jelbrekT1m3
//
//  Created by tihmstar on 18.07.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController{
    WCSession* session;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (void)session:(WCSession *)session activationDidCompleteWithState:(WCSessionActivationState)activationState error:(nullable NSError *)error{
    
}

- (void)sessionDidBecomeInactive:(WCSession *)session{
    
}

- (void)sessionDidDeactivate:(WCSession *)session{

}

@end
